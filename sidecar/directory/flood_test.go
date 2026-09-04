package directory

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/ndunl075/badge/sidecar/wba"
)

// An attacker names a new Signature-Agent origin on every request. Each one is
// a cache key, a breaker key and a potential outbound fetch, so every one of
// those structures has to stay bounded or the proxy is a memory-exhaustion
// primitive handed to anyone who can send requests.
//
// The bounds are asserted rather than assumed, because "it has an LRU" and "the
// LRU is actually reached on this path" are different claims, and the breaker
// map was missed the first time precisely because nobody checked.

func TestBoundedUnderOriginFlood(t *testing.T) {
	const (
		maxOrigins  = 64
		maxBreakers = 32
		floodSize   = 5000
	)

	failing := &recorder{fn: func(string, int) (*Response, error) {
		return nil, &ClientError{Message: "no such host", Kind: FailureNetwork}
	}}
	clock := wba.NewFixedClock(1000)
	r := New(Options{
		Fetcher:          failing,
		Clock:            clock,
		MaxOrigins:       maxOrigins,
		MaxBreakers:      maxBreakers,
		NegativeTTL:      3600,
		BreakerThreshold: 1,
		BreakerReset:     3600,
	})

	for i := 0; i < floodSize; i++ {
		origin := fmt.Sprintf("https://%d.attacker.example", i)
		r.Resolve(context.Background(), wba.KeyRequest{Origin: origin, Keyid: "x"})
	}

	stats := r.Stats()
	if stats.CachedOrigins > maxOrigins {
		t.Errorf("cache grew to %d entries, bound is %d", stats.CachedOrigins, maxOrigins)
	}
	if stats.Breakers > maxBreakers {
		t.Errorf("breaker map grew to %d entries, bound is %d", stats.Breakers, maxBreakers)
	}
	if stats.InFlight != 0 {
		t.Errorf("%d fetches still in flight after the flood", stats.InFlight)
	}
}

// A flood must not leak goroutines either. Background revalidation is fire and
// forget, so a leak there would accumulate silently under normal traffic.
func TestNoGoroutineLeakUnderFlood(t *testing.T) {
	http := &recorder{fn: func(string, int) (*Response, error) {
		return jwksResponse([]wba.JWK{testKey}, map[string]string{"cache-control": "max-age=1"}), nil
	}}
	clock := wba.NewFixedClock(1000)
	r := New(Options{Fetcher: http, Clock: clock, MaxOrigins: 16})
	keyid := testKeyid(t)

	settle()
	before := runtime.NumGoroutine()

	// Repeatedly age entries into the stale window so the background refresh
	// path runs over and over.
	for round := 0; round < 40; round++ {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				origin := fmt.Sprintf("https://%d.example", i)
				r.Resolve(context.Background(), wba.KeyRequest{Origin: origin, Keyid: keyid})
			}(i)
		}
		wg.Wait()
		clock.Advance(2)
	}

	settle()
	after := runtime.NumGoroutine()
	// A small allowance for runtime bookkeeping; a leak would be proportional to
	// the number of rounds, which is 320 resolves here.
	if after > before+16 {
		t.Errorf("goroutines grew from %d to %d across 320 resolves", before, after)
	}
}

func settle() {
	for i := 0; i < 12; i++ {
		runtime.GC()
		runtime.Gosched()
	}
}
