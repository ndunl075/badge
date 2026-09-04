// Command soak drives the proxy under sustained mixed traffic.
//
// It is the closest honest substitute for production hours: a real proxy in
// front of a real upstream, taking a realistic mix of unsigned, verified,
// forged and attacker-invented-origin traffic for as long as you ask, and
// reporting whether throughput, latency and memory stay flat.
//
// It is not a benchmark of peak throughput. The number that matters is whether
// resident memory and goroutine count are the same at the end as at the start
// while an attacker names a new Signature-Agent origin on every request.
//
//	go run ./cmd/soak -duration 60s -workers 32
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ndunl075/badge/sidecar/directory"
	"github.com/ndunl075/badge/sidecar/policy"
	"github.com/ndunl075/badge/sidecar/proxy"
	"github.com/ndunl075/badge/sidecar/wba"
)

const soakPolicy = `
version: 1
default: log-only
rules:
  - id: forgeries-are-hostile
    action: deny
    when: { class: untrusted }
  - id: allow-verified
    action: allow
    when: { status: verified }
`

func main() {
	duration := flag.Duration("duration", 30*time.Second, "how long to drive traffic")
	workers := flag.Int("workers", 16, "concurrent clients")
	flag.Parse()

	if err := run(*duration, *workers); err != nil {
		fmt.Fprintln(os.Stderr, "soak:", err)
		os.Exit(1)
	}
}

func run(duration time.Duration, workers int) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	jwk := wba.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
	keyid, err := wba.Thumbprint(jwk)
	if err != nil {
		return err
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	// A directory that serves the real key for the agent origin and 404s for
	// every origin an attacker invents.
	const agentOrigin = "https://agent.example"
	body, _ := json.Marshal(map[string]any{"keys": []wba.JWK{jwk}})
	resolver := directory.New(directory.Options{
		Fetcher: fetcherFunc(func(url string) (*directory.Response, error) {
			if url == agentOrigin+wba.DefaultProfile.DirectoryPath {
				headers := http.Header{}
				headers.Set("content-type", wba.DefaultProfile.DirectoryMediaType)
				return &directory.Response{Status: 200, Headers: headers, Body: body}, nil
			}
			return nil, &directory.ClientError{Message: "no such host", Kind: directory.FailureNetwork}
		}),
		MaxOrigins:  1024,
		MaxBreakers: 4096,
	})

	parsed, err := policy.Parse([]byte(soakPolicy))
	if err != nil {
		return err
	}
	engine, err := policy.Compile(*parsed)
	if err != nil {
		return err
	}
	upstreamHandler, err := proxy.NewUpstream(upstream.URL)
	if err != nil {
		return err
	}

	handler := &proxy.Handler{
		Verifier: wba.NewVerifier(resolver), Policy: engine,
		Upstream: upstreamHandler, Sink: discardSink{},
		Authority: proxy.AuthoritySource{Mode: "host"}, Scheme: proxy.SchemeSource{Mode: "auto"},
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	before := snapshot()
	fmt.Printf("start   %s\n", before)

	var (
		requests atomic.Int64
		statuses sync.Map
		latMu    sync.Mutex
		latency  []time.Duration
	)
	deadline := time.Now().Add(duration)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			client := &http.Client{Timeout: 10 * time.Second}
			local := make([]time.Duration, 0, 1024)
			for n := 0; time.Now().Before(deadline); n++ {
				req, err := buildRequest(server.URL, priv, keyid, agentOrigin, worker, n)
				if err != nil {
					continue
				}
				started := time.Now()
				res, err := client.Do(req)
				if err != nil {
					continue
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				local = append(local, time.Since(started))
				requests.Add(1)
				count, _ := statuses.LoadOrStore(res.StatusCode, new(atomic.Int64))
				count.(*atomic.Int64).Add(1)
			}
			latMu.Lock()
			latency = append(latency, local...)
			latMu.Unlock()
		}(w)
	}
	wg.Wait()

	after := snapshot()
	fmt.Printf("end     %s\n", after)

	total := requests.Load()
	fmt.Printf("\n%d requests in %s across %d workers (%.0f req/s)\n",
		total, duration, workers, float64(total)/duration.Seconds())

	statuses.Range(func(code, count any) bool {
		fmt.Printf("  HTTP %v: %d\n", code, count.(*atomic.Int64).Load())
		return true
	})

	sort.Slice(latency, func(i, j int) bool { return latency[i] < latency[j] })
	if len(latency) > 0 {
		at := func(q float64) time.Duration { return latency[int(float64(len(latency)-1)*q)] }
		fmt.Printf("  latency p50 %s  p95 %s  p99 %s  max %s\n",
			at(0.50).Round(time.Microsecond), at(0.95).Round(time.Microsecond),
			at(0.99).Round(time.Microsecond), latency[len(latency)-1].Round(time.Microsecond))
	}

	stats := resolver.Stats()
	fmt.Printf("\nresolver state after a flood of invented origins:\n")
	fmt.Printf("  cached origins %d (bound 1024)\n", stats.CachedOrigins)
	fmt.Printf("  breakers       %d (bound 4096)\n", stats.Breakers)
	fmt.Printf("  in flight      %d\n", stats.InFlight)

	if stats.CachedOrigins > 1024 || stats.Breakers > 4096 {
		return fmt.Errorf("bounded state exceeded its bound")
	}
	return nil
}

// buildRequest produces a realistic mix. The proportions matter: unsigned
// traffic is most of the internet, and the attacker case is the one that
// stresses the bounded structures.
func buildRequest(base string, priv ed25519.PrivateKey, keyid, agentOrigin string, worker, n int) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, base+"/docs/intro", nil)
	if err != nil {
		return nil, err
	}
	switch n % 10 {
	case 0, 1, 2, 3, 4, 5: // unsigned
		return req, nil
	case 6, 7: // verified
		return sign(req, priv, keyid, agentOrigin, false)
	case 8: // forged
		return sign(req, priv, keyid, agentOrigin, true)
	default: // an origin the attacker just invented
		return sign(req, priv, keyid, fmt.Sprintf("https://%d-%d.attacker.example", worker, n), false)
	}
}

func sign(req *http.Request, priv ed25519.PrivateKey, keyid, agentOrigin string, tamper bool) (*http.Request, error) {
	now := time.Now().Unix()
	signable := wba.NewRequest("GET", "http", req.URL.Host, req.URL.Path, "")
	signable.AddHeader("signature-agent", `"`+agentOrigin+`"`)

	fields, err := wba.Sign(signable, wba.SignOptions{
		PrivateKey: priv, Keyid: keyid, SignatureAgent: agentOrigin,
		Created: now, Expires: now + 60,
	})
	if err != nil {
		return nil, err
	}
	signature := fields.Signature
	if tamper {
		signature = signature[:len(signature)-6] + "AAAAA:"
	}
	req.Header.Set("signature-agent", `"`+agentOrigin+`"`)
	req.Header.Set("signature-input", fields.SignatureInput)
	req.Header.Set("signature", signature)
	return req, nil
}

func snapshot() string {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf("heap %5.1f MiB   goroutines %4d", float64(m.HeapAlloc)/(1024*1024), runtime.NumGoroutine())
}

type fetcherFunc func(url string) (*directory.Response, error)

func (f fetcherFunc) Get(_ context.Context, url string, _ time.Duration, _ int64, _ string) (*directory.Response, error) {
	return f(url)
}

type discardSink struct{}

func (discardSink) Record(proxy.Record) {}
