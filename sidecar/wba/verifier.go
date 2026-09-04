package wba

import (
	"context"
	"crypto/ed25519"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ndunl075/badge/sidecar/sfv"
)

// Verdict is the verifier's answer. It always carries a reason, including on
// success.
type Verdict struct {
	Status         Status   `json:"status"`
	Class          Class    `json:"class"`
	Reason         Reason   `json:"reason"`
	Profile        string   `json:"profile"`
	SignatureAgent string   `json:"signature_agent,omitempty"`
	Keyid          string   `json:"keyid,omitempty"`
	Label          string   `json:"label,omitempty"`
	Created        int64    `json:"created,omitempty"`
	Expires        int64    `json:"expires,omitempty"`
	Covered        []string `json:"covered,omitempty"`
	Cache          string   `json:"cache,omitempty"`
	TotalUs        int64    `json:"total_us"`
	DirectoryUs    int64    `json:"directory_us,omitempty"`
}

// Clock is injected so tests can move time without touching the system clock.
type Clock interface{ Now() int64 }

type systemClock struct{}

func (systemClock) Now() int64 { return time.Now().Unix() }

// SystemClock reads the real time.
var SystemClock Clock = systemClock{}

// FixedClock is a clock a test can move.
type FixedClock struct{ Seconds int64 }

func (c *FixedClock) Now() int64 { return c.Seconds }

// KeyRequest asks a resolver for one key.
type KeyRequest struct {
	Origin string
	Keyid  string
	Now    int64
}

// Resolution is a resolver's answer.
type Resolution struct {
	OK     bool
	Key    JWK
	Reason Reason
	Cache  string
}

// KeyResolver finds the public key a keyid refers to.
//
// This is the only part of verification that may do I/O, and it is an interface
// precisely so the network implementation — with its caches, timeouts and SSRF
// guard — stays out of the verifier.
type KeyResolver interface {
	Resolve(ctx context.Context, req KeyRequest) Resolution
}

// NonceStore is an atomic check-and-record for replay protection. It must be
// atomic across the whole enforcement boundary; a per-process store behind more
// than one replica is theatre.
type NonceStore interface {
	CheckAndRecord(ctx context.Context, nonce string, expiresAt int64) (fresh bool, err error)
}

// StaticKeys resolves from a fixed set, with no network access at all.
type StaticKeys map[string][]JWK

func (s StaticKeys) Resolve(_ context.Context, req KeyRequest) Resolution {
	for _, origin := range []string{req.Origin, "*"} {
		if origin == "" {
			continue
		}
		for _, key := range s[origin] {
			thumb, err := Thumbprint(key)
			if err != nil {
				continue
			}
			if thumb == req.Keyid {
				return Resolution{OK: true, Key: key, Cache: "hit"}
			}
		}
	}
	return Resolution{Reason: ReasonKeyNotFound, Cache: "hit"}
}

// Verifier applies one profile's rules to incoming requests.
type Verifier struct {
	Keys                 KeyResolver
	Profile              Profile
	Clock                Clock
	ClockSkewSec         int64
	MaxAgeSec            int64
	MinNonceBytes        int
	AllowedOrigins       []string
	Replay               NonceStore
	StructuredFieldTypes map[string]StructuredFieldType
}

// NewVerifier fills in the defaults.
func NewVerifier(keys KeyResolver) *Verifier {
	return &Verifier{
		Keys:          keys,
		Profile:       DefaultProfile,
		Clock:         SystemClock,
		ClockSkewSec:  5,
		MaxAgeSec:     300,
		MinNonceBytes: 16,
	}
}

type facts struct {
	profile     string
	agent       string
	keyid       string
	label       string
	created     int64
	expires     int64
	covered     []string
	cache       string
	directoryUs int64
}

func (f facts) verdict(reason Reason, elapsed time.Duration) Verdict {
	status, class := reason.Info()
	return Verdict{
		Status: status, Class: class, Reason: reason, Profile: f.profile,
		SignatureAgent: f.agent, Keyid: f.keyid, Label: f.label,
		Created: f.created, Expires: f.expires, Covered: f.covered,
		Cache: f.cache, TotalUs: elapsed.Microseconds(), DirectoryUs: f.directoryUs,
	}
}

var base64ish = regexp.MustCompile(`^[A-Za-z0-9+/_-]+={0,2}$`)

// Verify runs the eleven steps of the verification pipeline.
func (v *Verifier) Verify(ctx context.Context, req *Request) Verdict {
	started := time.Now()
	f := facts{profile: v.Profile.ID}
	done := func(reason Reason) Verdict { return f.verdict(reason, time.Since(started)) }

	// Step 1: the cheap presence test. Almost all production traffic exits here,
	// before any parsing, allocation or I/O.
	rawInput, hasInput := req.Header("signature-input")
	rawAgent, hasAgent := req.Header("signature-agent")
	if !hasInput {
		if !hasAgent {
			return done(ReasonNoSignatureFields)
		}
		return done(ReasonSignatureInputMalformed)
	}

	// Step 2: parse.
	inputs, err := sfv.ParseDictionary(rawInput)
	if err != nil {
		return done(ReasonSignatureInputMalformed)
	}
	rawSignature, hasSignature := req.Header("signature")
	if !hasSignature {
		return done(ReasonSignatureMalformed)
	}
	signatures, err := sfv.ParseDictionary(rawSignature)
	if err != nil {
		return done(ReasonSignatureMalformed)
	}

	// Step 3: select the Web Bot Auth signature; ignore any others.
	label, selected, ok := selectWebBotAuth(inputs, v.Profile.Tag)
	if !ok {
		return done(ReasonNoWebBotAuthTag)
	}
	f.label = label
	params := selected.Member.InnerList.Params
	components := selected.Member.InnerList.Items
	f.covered = make([]string, 0, len(components))
	for _, c := range components {
		if c.Value.Kind == sfv.KindString {
			f.covered = append(f.covered, c.Value.Str)
		} else {
			f.covered = append(f.covered, "?")
		}
	}

	// Step 4: preflight, cheapest and most attributable checks first.
	keyid, hasKeyid := params.GetString("keyid")
	if !hasKeyid {
		if v.Profile.RequireKeyid {
			return done(ReasonMissingKeyid)
		}
	} else {
		f.keyid = keyid
	}
	if alg, ok := params.GetString("alg"); ok && !contains(v.Profile.Algorithms, alg) {
		return done(ReasonUnsupportedAlgorithm)
	}
	created, hasCreated := params.GetInteger("created")
	if !hasCreated {
		if v.Profile.RequireCreated {
			return done(ReasonMissingCreated)
		}
	} else {
		f.created = created
	}
	expires, hasExpires := params.GetInteger("expires")
	if !hasExpires {
		if v.Profile.RequireExpires {
			return done(ReasonMissingExpires)
		}
	} else {
		f.expires = expires
	}

	if reason, bad := checkCovered(components, req, v.Profile); bad {
		return done(reason)
	}

	// Step 5: identity of the directory.
	origin := ""
	if hasAgent {
		parsed, ok := parseSignatureAgent(rawAgent)
		if !ok {
			return done(ReasonSignatureAgentMalformed)
		}
		origin = parsed
		f.agent = parsed
	} else if v.Profile.RequireSignatureAgent {
		return done(ReasonSignatureAgentMissing)
	}
	if v.AllowedOrigins != nil && (origin == "" || !contains(v.AllowedOrigins, origin)) {
		return done(ReasonSignatureAgentNotAllowed)
	}

	// Step 6: the window. Structural problems are reported before expiry, so a
	// nonsense window reads as malformed rather than merely stale.
	now := v.Clock.Now()
	if hasCreated && hasExpires {
		if expires-created > v.Profile.MaxWindowSec || expires < created {
			return done(ReasonValidityWindowTooLong)
		}
	}
	if hasCreated && created > now+v.ClockSkewSec {
		return done(ReasonCreatedInFuture)
	}
	if hasExpires && now-v.ClockSkewSec > expires {
		return done(ReasonSignatureExpired)
	}
	if hasCreated && now-created > v.MaxAgeSec {
		return done(ReasonSignatureTooOld)
	}

	// Step 7: the signature bytes.
	signatureBytes, ok := signatureFor(signatures, label)
	if !ok {
		return done(ReasonSignatureMalformed)
	}

	// Step 8: reconstruct the base.
	base, err := BuildBase(req, components, selected.Source, v.StructuredFieldTypes)
	if err != nil {
		if be, ok := err.(*BaseError); ok {
			return done(be.Reason)
		}
		return done(ReasonInternalError)
	}

	// Step 9: resolve the key. The only I/O in the pipeline.
	if !hasKeyid {
		return done(ReasonMissingKeyid)
	}
	directoryStarted := time.Now()
	resolution := v.Keys.Resolve(ctx, KeyRequest{Origin: origin, Keyid: keyid, Now: now})
	f.directoryUs = time.Since(directoryStarted).Microseconds()
	f.cache = resolution.Cache
	if !resolution.OK {
		return done(resolution.Reason)
	}
	if !IsEd25519(resolution.Key) {
		return done(ReasonUnsupportedAlgorithm)
	}
	switch KeyValidityAt(resolution.Key, now) {
	case ValidityNotYetValid:
		return done(ReasonKeyNotYetValid)
	case ValidityExpired:
		return done(ReasonKeyExpired)
	}

	// Step 10: verify.
	pub, err := PublicKey(resolution.Key)
	if err != nil {
		return done(ReasonUnsupportedAlgorithm)
	}
	if !ed25519.Verify(pub, []byte(base), signatureBytes) {
		return done(ReasonSignatureInvalid)
	}

	// Step 11: replay, only when a store is configured.
	if v.Replay != nil {
		nonce, ok := params.GetString("nonce")
		if !ok {
			return done(ReasonNonceMissing)
		}
		if decodedNonceBytes(nonce) < v.MinNonceBytes {
			return done(ReasonNonceInvalid)
		}
		fresh, err := v.Replay.CheckAndRecord(ctx, nonce, v.replayRetainUntil(hasCreated, created, hasExpires, expires, now))
		if err != nil {
			// A store outage must never read as a replay: that would deny
			// legitimate traffic the moment the store hiccups.
			return done(ReasonNonceStoreUnavailable)
		}
		if !fresh {
			return done(ReasonReplayDetected)
		}
	}

	return done(ReasonOK)
}

// replayRetainUntil is the last instant this signature could still be accepted.
//
// Remembering a nonce only until expires would leave the signature replayable
// for the final ClockSkewSec seconds of its own acceptance window. Acceptance
// needs both the expiry and the age check to hold, so the earlier bound is the
// real deadline.
func (v *Verifier) replayRetainUntil(hasCreated bool, created int64, hasExpires bool, expires, now int64) int64 {
	byExpiry := now + v.ClockSkewSec
	if hasExpires {
		byExpiry = expires + v.ClockSkewSec
	}
	if !hasCreated {
		return byExpiry
	}
	byAge := created + v.MaxAgeSec
	if byAge < byExpiry {
		return byAge
	}
	return byExpiry
}

// decodedNonceBytes returns the decoded length of a base64 or base64url nonce,
// or 0 if it is neither. Computed from the encoded length rather than by
// decoding: the value is attacker-controlled and there is no reason to allocate.
func decodedNonceBytes(nonce string) int {
	if !base64ish.MatchString(nonce) {
		return 0
	}
	unpadded := strings.TrimRight(nonce, "=")
	return len(unpadded) * 3 / 4
}

// selectWebBotAuth picks the first signature tagged for Web Bot Auth. The tag
// must be a String; a Token spelling web-bot-auth is a different RFC 9651 value.
func selectWebBotAuth(inputs *sfv.Dictionary, tag string) (string, sfv.DictEntry, bool) {
	for _, label := range inputs.Keys() {
		entry, _ := inputs.Get(label)
		if !entry.Member.IsInnerList {
			continue
		}
		value, ok := entry.Member.InnerList.Params.GetString("tag")
		if !ok || value != tag {
			continue
		}
		return label, entry, true
	}
	return "", sfv.DictEntry{}, false
}

func checkCovered(components []sfv.Item, req *Request, profile Profile) (Reason, bool) {
	names := map[string]bool{}
	for _, component := range components {
		if component.Value.Kind != sfv.KindString {
			return ReasonSignatureInputMalformed, true
		}
		names[component.Value.Str] = true
	}
	// Each group is satisfied by any one of its members, so a signature over
	// @target-uri satisfies the @authority requirement it subsumes.
	for _, group := range profile.RequiredComponents {
		satisfied := false
		for _, name := range group {
			if names[name] {
				satisfied = true
				break
			}
		}
		if !satisfied {
			return ReasonCoveredComponentsInsufficient, true
		}
	}
	for _, required := range profile.RequiredComponentsWhenPresent {
		if _, present := req.Header(required); present && !names[required] {
			return ReasonCoveredComponentsInsufficient, true
		}
	}
	return "", false
}

// parseSignatureAgent reads the structured field String holding an absolute
// https URI. Anything else — a bare token, an http URI, a path — is malformed.
func parseSignatureAgent(raw string) (string, bool) {
	item, err := sfv.ParseItem(raw)
	if err != nil || item.Value.Kind != sfv.KindString {
		return "", false
	}
	parsed, err := url.Parse(item.Value.Str)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", false
	}
	return parsed.Scheme + "://" + parsed.Host, true
}

func signatureFor(signatures *sfv.Dictionary, label string) ([]byte, bool) {
	entry, ok := signatures.Get(label)
	if !ok || entry.Member.IsInnerList {
		return nil, false
	}
	if entry.Member.Item.Value.Kind != sfv.KindBinary {
		return nil, false
	}
	return entry.Member.Item.Value.Bin, true
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
