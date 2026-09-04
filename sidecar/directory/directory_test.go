package directory

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ndunl075/badge/sidecar/wba"
)

func TestIsPublicAddress(t *testing.T) {
	public := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "::ffff:1.1.1.1"}
	for _, ip := range public {
		if !ParsePublicAddress(ip) {
			t.Errorf("%s should be public", ip)
		}
	}

	blocked := []string{
		"127.0.0.1", "127.1.2.3", "0.0.0.0", "10.0.0.1", "172.16.0.1", "172.31.255.254",
		"192.168.1.1", "100.64.0.1", "169.254.1.1", "169.254.169.254", "255.255.255.255",
		"224.0.0.1", "198.18.0.1", "192.88.99.1",
		"::1", "::", "fd00::1", "fe80::1", "ff02::1", "2001:db8::1",
		// Transition mechanisms embedding an IPv4 address.
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::127.0.0.1",
		"64:ff9b::127.0.0.1", "2002:7f00:1::", "2002:a9fe:a9fe::",
		"2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:20::1", "2001:2::1",
		"100::1", "3fff::1", "5f00::1",
	}
	for _, ip := range blocked {
		if ParsePublicAddress(ip) {
			t.Errorf("%s should be refused", ip)
		}
	}

	// Anything we cannot classify, we cannot vouch for.
	for _, ip := range []string{"", "not-an-ip", "1.2.3", "1.2.3.4.5", "256.1.1.1", "010.0.0.1"} {
		if ParsePublicAddress(ip) {
			t.Errorf("%s should be refused as unparseable", ip)
		}
	}
}

type recorder struct {
	mu    sync.Mutex
	calls []string
	fn    func(url string, call int) (*Response, error)
}

func (r *recorder) Get(_ context.Context, url string, _ time.Duration, _ int64, _ string) (*Response, error) {
	r.mu.Lock()
	r.calls = append(r.calls, url)
	n := len(r.calls)
	r.mu.Unlock()
	return r.fn(url, n)
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func jwksResponse(keys []wba.JWK, headers map[string]string) *Response {
	body, _ := json.Marshal(map[string]any{"keys": keys})
	h := http.Header{}
	h.Set("content-type", "application/http-message-signatures-directory+json")
	for k, v := range headers {
		h.Set(k, v)
	}
	return &Response{Status: 200, Headers: h, Body: body}
}

const testOrigin = "https://agent.example"

var testKey = wba.JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}

func testKeyid(t *testing.T) string {
	t.Helper()
	id, err := wba.Thumbprint(testKey)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return id
}

func TestResolverFetchesAndCaches(t *testing.T) {
	http := &recorder{fn: func(string, int) (*Response, error) { return jwksResponse([]wba.JWK{testKey}, nil), nil }}
	clock := &wba.FixedClock{Seconds: 1000}
	r := New(Options{Fetcher: http, Clock: clock})
	keyid := testKeyid(t)

	first := r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: keyid})
	if !first.OK || first.Cache != "miss" {
		t.Fatalf("first resolve = %+v", first)
	}
	if got := http.calls[0]; got != testOrigin+"/.well-known/http-message-signatures-directory" {
		t.Errorf("fetched %q", got)
	}

	second := r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: keyid})
	if !second.OK || second.Cache != "hit" {
		t.Errorf("second resolve = %+v", second)
	}
	if http.count() != 1 {
		t.Errorf("fetched %d times, want 1", http.count())
	}
}

func TestResolverServesStaleWhileRevalidating(t *testing.T) {
	http := &recorder{fn: func(string, int) (*Response, error) {
		return jwksResponse([]wba.JWK{testKey}, map[string]string{"cache-control": "max-age=60"}), nil
	}}
	clock := &wba.FixedClock{Seconds: 1000}
	r := New(Options{Fetcher: http, Clock: clock})
	keyid := testKeyid(t)

	r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: keyid})
	clock.Seconds += 61
	got := r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: keyid})
	if !got.OK || got.Cache != "stale" {
		t.Fatalf("stale resolve = %+v", got)
	}
	time.Sleep(50 * time.Millisecond)
	if http.count() < 2 {
		t.Errorf("background refresh did not run, calls = %d", http.count())
	}
}

// The stale window exists to keep serving while an origin is unwell, so a
// failed refresh must not evict good keys.
func TestFailedRefreshKeepsGoodKeys(t *testing.T) {
	var healthy = true
	var mu sync.Mutex
	http := &recorder{fn: func(string, int) (*Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if !healthy {
			return nil, &ClientError{Message: "down", Kind: FailureNetwork}
		}
		return jwksResponse([]wba.JWK{testKey}, map[string]string{"cache-control": "max-age=60"}), nil
	}}
	clock := &wba.FixedClock{Seconds: 1000}
	r := New(Options{Fetcher: http, Clock: clock})
	keyid := testKeyid(t)

	r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: keyid})
	mu.Lock()
	healthy = false
	mu.Unlock()
	clock.Seconds += 100

	if got := r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: keyid}); !got.OK {
		t.Fatalf("stale resolve should still serve keys, got %+v", got)
	}
	time.Sleep(50 * time.Millisecond)
	if got := r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: keyid}); !got.OK {
		t.Errorf("a failed refresh evicted good keys: %+v", got)
	}
}

func TestResolverTransportFailureMapping(t *testing.T) {
	cases := map[FailureKind]wba.Reason{
		FailureTimeout:  wba.ReasonDirectoryTimeout,
		FailureTooLarge: wba.ReasonDirectoryTooLarge,
		FailureBlocked:  wba.ReasonDirectoryUnreachable,
		FailureNetwork:  wba.ReasonDirectoryUnreachable,
	}
	for kind, want := range cases {
		http := &recorder{fn: func(string, int) (*Response, error) {
			return nil, &ClientError{Message: "nope", Kind: kind}
		}}
		r := New(Options{Fetcher: http, Clock: &wba.FixedClock{Seconds: 1000}})
		got := r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: "x"})
		if got.Reason != want {
			t.Errorf("%s -> %q, want %q", kind, got.Reason, want)
		}
	}
}

func TestResolverNegativeCaching(t *testing.T) {
	http := &recorder{fn: func(string, int) (*Response, error) {
		return nil, &ClientError{Message: "down", Kind: FailureNetwork}
	}}
	clock := &wba.FixedClock{Seconds: 1000}
	r := New(Options{Fetcher: http, Clock: clock})

	r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: "x"})
	r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: "x"})
	if http.count() != 1 {
		t.Errorf("a broken directory was hammered: %d calls", http.count())
	}
}

func TestResolverBreakerOpensAndCloses(t *testing.T) {
	var healthy = false
	var mu sync.Mutex
	http := &recorder{fn: func(string, int) (*Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if !healthy {
			return nil, &ClientError{Message: "down", Kind: FailureNetwork}
		}
		return jwksResponse([]wba.JWK{testKey}, nil), nil
	}}
	clock := &wba.FixedClock{Seconds: 1000}
	r := New(Options{Fetcher: http, Clock: clock, NegativeTTL: 1, BreakerThreshold: 2, BreakerReset: 30})

	for i := 0; i < 2; i++ {
		r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: "x"})
		clock.Seconds += 2
	}
	before := http.count()
	r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: "x"})
	if http.count() != before {
		t.Errorf("open breaker still opened a socket")
	}

	mu.Lock()
	healthy = true
	mu.Unlock()
	clock.Seconds += 31
	if got := r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: testKeyid(t)}); !got.OK {
		t.Errorf("breaker did not close: %+v", got)
	}
}

func TestResolverAllowlist(t *testing.T) {
	http := &recorder{fn: func(string, int) (*Response, error) { return jwksResponse([]wba.JWK{testKey}, nil), nil }}
	r := New(Options{Fetcher: http, Clock: &wba.FixedClock{Seconds: 1000}, AllowedOrigins: []string{"https://known.example"}})
	got := r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: "x"})
	if got.Reason != wba.ReasonSignatureAgentNotAllowed {
		t.Errorf("reason = %q", got.Reason)
	}
	if http.count() != 0 {
		t.Errorf("an origin outside the allowlist was fetched")
	}
}

func TestResolverMediaType(t *testing.T) {
	plainJSON := map[string]string{"content-type": "application/json"}

	lenient := New(Options{
		Fetcher: &recorder{fn: func(string, int) (*Response, error) { return jwksResponse([]wba.JWK{testKey}, plainJSON), nil }},
		Clock:   &wba.FixedClock{Seconds: 1000},
	})
	if got := lenient.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: testKeyid(t)}); !got.OK {
		t.Errorf("lenient mode should accept application/json: %+v", got)
	}

	strict := New(Options{
		Fetcher:         &recorder{fn: func(string, int) (*Response, error) { return jwksResponse([]wba.JWK{testKey}, plainJSON), nil }},
		Clock:           &wba.FixedClock{Seconds: 1000},
		StrictMediaType: true,
	})
	if got := strict.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: testKeyid(t)}); got.Reason != wba.ReasonDirectoryMalformed {
		t.Errorf("strict mode reason = %q", got.Reason)
	}
}

func TestResolverMalformedBodies(t *testing.T) {
	bodies := [][]byte{[]byte("{oops"), []byte(`{"nope":1}`)}
	for _, body := range bodies {
		h := http.Header{}
		h.Set("content-type", "application/json")
		r := New(Options{
			Fetcher: &recorder{fn: func(string, int) (*Response, error) {
				return &Response{Status: 200, Headers: h, Body: body}, nil
			}},
			Clock: &wba.FixedClock{Seconds: 1000},
		})
		got := r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: "x"})
		if got.Reason != wba.ReasonDirectoryMalformed {
			t.Errorf("body %q -> %q", body, got.Reason)
		}
	}
}

func TestResolverSingleFlight(t *testing.T) {
	release := make(chan struct{})
	http := &recorder{fn: func(string, int) (*Response, error) {
		<-release
		return jwksResponse([]wba.JWK{testKey}, nil), nil
	}}
	r := New(Options{Fetcher: http, Clock: &wba.FixedClock{Seconds: 1000}})
	keyid := testKeyid(t)

	var wg sync.WaitGroup
	results := make([]wba.Resolution, 5)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = r.Resolve(context.Background(), wba.KeyRequest{Origin: testOrigin, Keyid: keyid})
		}(i)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, got := range results {
		if !got.OK {
			t.Errorf("result %d = %+v", i, got)
		}
	}
	if http.count() != 1 {
		t.Errorf("fetched %d times, want 1", http.count())
	}
}
