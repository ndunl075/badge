package directory

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ndunl075/badge/sidecar/wba"
)

// entry is what the cache holds for one origin.
type entry struct {
	keys       []wba.JWK
	failure    wba.Reason
	freshUntil int64
	staleUntil int64
}

// Options configures the resolver. Every limit here bounds what
// attacker-controlled input can cost, because the origin comes from the caller.
type Options struct {
	Fetcher              Fetcher
	Profile              wba.Profile
	Clock                wba.Clock
	Timeout              time.Duration
	MaxBytes             int64
	MaxKeys              int
	MinTTL               int64
	MaxTTL               int64
	DefaultTTL           int64
	StaleWhileRevalidate int64
	NegativeTTL          int64
	MaxOrigins           int
	MaxConcurrentFetches int
	MaxBreakers          int
	BreakerThreshold     int
	BreakerReset         int64
	AllowedOrigins       []string
	// StrictMediaType requires the media type the draft mandates. The default
	// is lenient, because plenty of real directories are served by a static
	// host that has never heard of it, and refusing those turns an interop wart
	// into an outage.
	StrictMediaType bool
}

func (o *Options) withDefaults() {
	if o.Fetcher == nil {
		o.Fetcher = NewHTTPFetcher(ClientOptions{})
	}
	if o.Profile.ID == "" {
		o.Profile = wba.DefaultProfile
	}
	if o.Clock == nil {
		o.Clock = wba.SystemClock
	}
	if o.Timeout == 0 {
		o.Timeout = time.Second
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = 256 * 1024
	}
	if o.MaxKeys == 0 {
		o.MaxKeys = 100
	}
	if o.MinTTL == 0 {
		o.MinTTL = 60
	}
	if o.MaxTTL == 0 {
		o.MaxTTL = 3600
	}
	if o.DefaultTTL == 0 {
		o.DefaultTTL = 300
	}
	if o.StaleWhileRevalidate == 0 {
		o.StaleWhileRevalidate = 86400
	}
	if o.NegativeTTL == 0 {
		o.NegativeTTL = 30
	}
	if o.MaxOrigins == 0 {
		o.MaxOrigins = 1024
	}
	if o.MaxConcurrentFetches == 0 {
		o.MaxConcurrentFetches = 32
	}
	if o.MaxBreakers == 0 {
		o.MaxBreakers = 4096
	}
	if o.BreakerThreshold == 0 {
		o.BreakerThreshold = 5
	}
	if o.BreakerReset == 0 {
		o.BreakerReset = 30
	}
}

type breaker struct {
	failures  int
	openUntil int64
}

// Resolver turns an origin and a keyid into a key, or into a reason, without
// letting a live request wait on network it does not strictly need.
type Resolver struct {
	opts Options

	mu       sync.Mutex
	cache    map[string]*entry
	order    []string
	breakers map[string]*breaker
	inFlight map[string]chan struct{}
	pending  map[string]*entry
}

func New(opts Options) *Resolver {
	opts.withDefaults()
	return &Resolver{
		opts:     opts,
		cache:    map[string]*entry{},
		breakers: map[string]*breaker{},
		inFlight: map[string]chan struct{}{},
		pending:  map[string]*entry{},
	}
}

// Resolve implements wba.KeyResolver.
func (r *Resolver) Resolve(ctx context.Context, req wba.KeyRequest) wba.Resolution {
	if req.Origin == "" {
		return wba.Resolution{Reason: wba.ReasonKeyNotFound}
	}
	if r.opts.AllowedOrigins != nil && !contains(r.opts.AllowedOrigins, req.Origin) {
		return wba.Resolution{Reason: wba.ReasonSignatureAgentNotAllowed}
	}

	now := r.opts.Clock.Now()
	cached, breakerOpen := r.snapshot(req.Origin, now)

	if cached != nil && now < cached.freshUntil {
		return answer(cached, req.Keyid, "hit")
	}
	if cached != nil && now < cached.staleUntil {
		// Serve what we have and refresh behind the request. The alternative is
		// a synchronous fetch on a live request path, which is what this cache
		// exists to avoid.
		if !breakerOpen {
			go r.refresh(context.WithoutCancel(ctx), req.Origin)
		}
		return answer(cached, req.Keyid, "stale")
	}
	if breakerOpen {
		return wba.Resolution{Reason: wba.ReasonDirectoryUnreachable, Cache: "miss"}
	}

	fresh, cacheable := r.fetchOnce(ctx, req.Origin)
	if cacheable {
		r.store(req.Origin, fresh)
	}
	return answer(fresh, req.Keyid, "miss")
}

func (r *Resolver) snapshot(origin string, now int64) (*entry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cached := r.cache[origin]
	if cached != nil {
		r.touchLocked(origin)
	}
	b := r.breakers[origin]
	return cached, b != nil && now < b.openUntil
}

func (r *Resolver) refresh(ctx context.Context, origin string) {
	fresh, cacheable := r.fetchOnce(ctx, origin)
	// Never overwrite a usable stale entry with a failure. The stale window
	// exists to keep serving while the origin is unwell; replacing good keys
	// with a short negative entry would throw away the rest of it and hand
	// every caller of that origin an unverifiable verdict.
	if cacheable && fresh.failure == "" {
		r.store(origin, fresh)
	}
}

// fetchOnce runs one fetch per origin at a time, however many requests wait.
//
// The second return value is false when the attempt never reached the network,
// because the local concurrency valve refused it. Caching that would blame an
// origin that was never contacted.
func (r *Resolver) fetchOnce(ctx context.Context, origin string) (*entry, bool) {
	r.mu.Lock()
	if wait, ok := r.inFlight[origin]; ok {
		r.mu.Unlock()
		<-wait
		r.mu.Lock()
		result := r.pending[origin]
		r.mu.Unlock()
		if result == nil {
			return r.failureEntry(wba.ReasonDirectoryUnreachable), false
		}
		return result, true
	}
	if len(r.inFlight) >= r.opts.MaxConcurrentFetches {
		r.mu.Unlock()
		// Refusing beats queueing: an attacker naming thousands of origins
		// would otherwise turn request concurrency into unbounded outbound
		// fan-out.
		return r.failureEntry(wba.ReasonDirectoryUnreachable), false
	}
	wait := make(chan struct{})
	r.inFlight[origin] = wait
	r.mu.Unlock()

	result := r.fetch(ctx, origin)

	r.mu.Lock()
	r.pending[origin] = result
	delete(r.inFlight, origin)
	close(wait)
	r.mu.Unlock()

	// Let waiters read pending, then drop it.
	go func() {
		time.Sleep(time.Millisecond)
		r.mu.Lock()
		delete(r.pending, origin)
		r.mu.Unlock()
	}()

	return result, true
}

func (r *Resolver) fetch(ctx context.Context, origin string) *entry {
	accept := r.opts.Profile.DirectoryMediaType + ", application/json;q=0.9"
	res, err := r.opts.Fetcher.Get(ctx, origin+r.opts.Profile.DirectoryPath, r.opts.Timeout, r.opts.MaxBytes, accept)
	if err != nil {
		r.recordFailure(origin)
		return r.failureEntry(reasonForTransport(err))
	}
	if res.Status != 200 {
		r.recordFailure(origin)
		return r.failureEntry(wba.ReasonDirectoryUnreachable)
	}
	if !mediaTypeAcceptable(res.Headers.Get("content-type"), r.opts.Profile, r.opts.StrictMediaType) {
		return r.failureEntry(wba.ReasonDirectoryMalformed)
	}

	var doc struct {
		Keys []wba.JWK `json:"keys"`
	}
	if err := json.Unmarshal(res.Body, &doc); err != nil || doc.Keys == nil {
		return r.failureEntry(wba.ReasonDirectoryMalformed)
	}
	if len(doc.Keys) > r.opts.MaxKeys {
		return r.failureEntry(wba.ReasonDirectoryTooLarge)
	}

	r.clearBreaker(origin)
	now := r.opts.Clock.Now()
	ttl := r.clampTTL(res.Headers.Get("cache-control"))
	return &entry{keys: doc.Keys, freshUntil: now + ttl, staleUntil: now + ttl + r.opts.StaleWhileRevalidate}
}

func (r *Resolver) failureEntry(reason wba.Reason) *entry {
	now := r.opts.Clock.Now()
	// A cached failure is never served stale: once it lapses we try again.
	return &entry{failure: reason, freshUntil: now + r.opts.NegativeTTL, staleUntil: now + r.opts.NegativeTTL}
}

// clampTTL treats the directory's Cache-Control as advisory.
//
// The floor is the important half: without it an origin could send max-age=0 or
// no-store and make the proxy fetch its directory on every single request, an
// amplification hazard pointed at us by someone else's configuration.
func (r *Resolver) clampTTL(cacheControl string) int64 {
	maxAge, ok := parseMaxAge(cacheControl)
	if !ok {
		return r.opts.DefaultTTL
	}
	if maxAge < r.opts.MinTTL {
		maxAge = r.opts.MinTTL
	}
	if maxAge > r.opts.MaxTTL {
		maxAge = r.opts.MaxTTL
	}
	return maxAge
}

func (r *Resolver) store(origin string, e *entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, seen := r.cache[origin]; !seen {
		r.order = append(r.order, origin)
	} else {
		r.touchLocked(origin)
	}
	r.cache[origin] = e
	// Origins come from attacker-controlled input, so the cache is bounded: an
	// unbounded map is a memory-exhaustion primitive.
	for len(r.order) > r.opts.MaxOrigins {
		oldest := r.order[0]
		r.order = r.order[1:]
		delete(r.cache, oldest)
	}
}

func (r *Resolver) touchLocked(origin string) {
	for i, name := range r.order {
		if name == origin {
			r.order = append(append(r.order[:i:i], r.order[i+1:]...), origin)
			return
		}
	}
	r.order = append(r.order, origin)
}

func (r *Resolver) recordFailure(origin string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.breakers[origin]
	if b == nil {
		b = &breaker{}
		r.breakers[origin] = b
	}
	b.failures++
	if b.failures >= r.opts.BreakerThreshold {
		b.openUntil = r.opts.Clock.Now() + r.opts.BreakerReset
	}
	// Breakers are keyed by the attacker-supplied origin, so the map is bounded
	// too. Evicting a breaker only means an origin may be tried again, which is
	// safe — unlike evicting a nonce.
	if len(r.breakers) > r.opts.MaxBreakers {
		now := r.opts.Clock.Now()
		for name, other := range r.breakers {
			if other.openUntil <= now && name != origin {
				delete(r.breakers, name)
			}
		}
		for name := range r.breakers {
			if len(r.breakers) <= r.opts.MaxBreakers {
				break
			}
			if name != origin {
				delete(r.breakers, name)
			}
		}
	}
}

// Stats reports the size of the resolver's bounded state.
//
// Every one of these is keyed by the attacker-supplied Signature-Agent origin,
// so an operator wants to see them on a dashboard, and a test wants to assert
// they stay bounded under a flood of invented origins.
type Stats struct {
	CachedOrigins int
	Breakers      int
	InFlight      int
}

func (r *Resolver) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Stats{CachedOrigins: len(r.cache), Breakers: len(r.breakers), InFlight: len(r.inFlight)}
}

func (r *Resolver) clearBreaker(origin string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.breakers, origin)
}

func answer(e *entry, keyid, cache string) wba.Resolution {
	if e.failure != "" {
		return wba.Resolution{Reason: e.failure, Cache: cache}
	}
	for _, key := range e.keys {
		thumb, err := wba.Thumbprint(key)
		if err != nil {
			// A key we cannot thumbprint simply is not this key. One bad entry
			// must not poison the whole directory.
			continue
		}
		if thumb == keyid {
			return wba.Resolution{OK: true, Key: key, Cache: cache}
		}
	}
	return wba.Resolution{Reason: wba.ReasonKeyNotFound, Cache: cache}
}

func reasonForTransport(err error) wba.Reason {
	clientErr, ok := err.(*ClientError)
	if !ok {
		return wba.ReasonDirectoryUnreachable
	}
	switch clientErr.Kind {
	case FailureTimeout:
		return wba.ReasonDirectoryTimeout
	case FailureTooLarge:
		return wba.ReasonDirectoryTooLarge
	default:
		return wba.ReasonDirectoryUnreachable
	}
}

func mediaTypeAcceptable(contentType string, profile wba.Profile, strict bool) bool {
	if contentType == "" {
		return !strict
	}
	essence := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if essence == profile.DirectoryMediaType {
		return true
	}
	if strict {
		return false
	}
	return essence == "application/json" || strings.HasSuffix(essence, "+json")
}

func parseMaxAge(cacheControl string) (int64, bool) {
	if cacheControl == "" {
		return 0, false
	}
	lower := strings.ToLower(cacheControl)
	for _, directive := range strings.Split(lower, ",") {
		directive = strings.TrimSpace(directive)
		// Zero rather than absent: the caller clamps it to the floor, so a
		// directory asking not to be cached gets the shortest lifetime the
		// proxy offers instead of the default one.
		if directive == "no-store" || directive == "no-cache" {
			return 0, true
		}
		if value, ok := strings.CutPrefix(directive, "max-age="); ok {
			n, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64)
			if err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
