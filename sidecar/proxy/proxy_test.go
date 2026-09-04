package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ndunl075/badge/sidecar/policy"
	"github.com/ndunl075/badge/sidecar/wba"
)

const (
	testNow    = int64(1735689600)
	testOrigin = "https://agent.example"
)

type collector struct{ records []Record }

func (c *collector) Record(r Record) { c.records = append(c.records, r) }

func newKey(t *testing.T) (ed25519.PrivateKey, wba.JWK, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk := wba.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
	keyid, err := wba.Thumbprint(jwk)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return priv, jwk, keyid
}

// harness stands up a real upstream behind a real proxy.
type harness struct {
	upstream *httptest.Server
	proxy    *httptest.Server
	sink     *collector
	priv     ed25519.PrivateKey
	keyid    string
}

func newHarness(t *testing.T, source string, tweak func(*Handler)) *harness {
	t.Helper()
	priv, jwk, keyid := newKey(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-upstream-path", r.URL.Path)
		_, _ = w.Write([]byte("the application handled this request"))
	}))
	t.Cleanup(upstream.Close)

	parsed, err := policy.Parse([]byte(source))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	engine, err := policy.Compile(*parsed)
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	upstreamHandler, err := NewUpstream(upstream.URL)
	if err != nil {
		t.Fatalf("NewUpstream: %v", err)
	}

	verifier := wba.NewVerifier(wba.StaticKeys{testOrigin: {jwk}})
	verifier.Clock = wba.NewFixedClock(testNow)

	sink := &collector{}
	handler := &Handler{
		Verifier: verifier, Policy: engine, Upstream: upstreamHandler, Sink: sink,
		Authority: AuthoritySource{Mode: "host"}, Scheme: SchemeSource{Mode: "auto"},
	}
	if tweak != nil {
		tweak(handler)
	}

	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)

	return &harness{upstream: upstream, proxy: proxy, sink: sink, priv: priv, keyid: keyid}
}

func (h *harness) sign(t *testing.T, method, path string, opts wba.SignOptions) http.Header {
	t.Helper()
	authority := strings.TrimPrefix(h.proxy.URL, "http://")
	req := wba.NewRequest(method, "http", authority, path, "")
	req.AddHeader("signature-agent", `"`+testOrigin+`"`)

	opts.PrivateKey = h.priv
	opts.Keyid = h.keyid
	opts.SignatureAgent = testOrigin
	if opts.Created == 0 {
		opts.Created = testNow
	}
	if opts.Expires == 0 {
		opts.Expires = testNow + 60
	}
	fields, err := wba.Sign(req, opts)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	headers := http.Header{}
	headers.Set("signature-agent", `"`+testOrigin+`"`)
	headers.Set("signature-input", fields.SignatureInput)
	headers.Set("signature", fields.Signature)
	return headers
}

func (h *harness) do(t *testing.T, method, path string, headers http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, h.proxy.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	res, err := h.proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

const proxyPolicy = `
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

func TestProxyForwardsUnsignedTraffic(t *testing.T) {
	h := newHarness(t, proxyPolicy, nil)
	res := h.do(t, "GET", "/docs/intro", nil)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if got := res.Header.Get("x-upstream-path"); got != "/docs/intro" {
		t.Errorf("upstream path = %q", got)
	}
	if last := h.sink.records[len(h.sink.records)-1]; last.Reason != "no_signature_fields" {
		t.Errorf("reason = %q", last.Reason)
	}
}

func TestProxyVerifiesAndForwards(t *testing.T) {
	h := newHarness(t, proxyPolicy, nil)
	res := h.do(t, "GET", "/docs/intro", h.sign(t, "GET", "/docs/intro", wba.SignOptions{}))
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	record := h.sink.records[len(h.sink.records)-1]
	if record.Reason != "ok" || record.Status != "verified" || record.Rule != "allow-verified" {
		t.Errorf("record = %+v", record)
	}
	if record.Keyid != h.keyid {
		t.Errorf("keyid = %q", record.Keyid)
	}
}

func TestProxyDeniesForgeries(t *testing.T) {
	h := newHarness(t, proxyPolicy, nil)
	headers := h.sign(t, "GET", "/docs/intro", wba.SignOptions{})
	// Flip one byte of the signature itself, leaving the encoding and every
	// other field valid, so this exercises signature_invalid rather than a
	// malformed field.
	headers.Set("signature", tamper(t, headers.Get("signature")))

	res := h.do(t, "GET", "/docs/intro", headers)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.StatusCode)
	}
	// A denial is specific to this caller's credentials and must never be
	// stored by a shared cache in front of the origin.
	if got := res.Header.Get("cache-control"); got != "no-store" {
		t.Errorf("cache-control = %q", got)
	}
	if got := res.Header.Get("x-upstream-path"); got != "" {
		t.Errorf("a denied request reached the upstream")
	}
}

// The failure the architecture keeps warning about: a proxy rewrites Host and
// the verdict looks cryptographic.
// tamper flips a byte inside the encoded signature, keeping it well-formed.
func tamper(t *testing.T, header string) string {
	t.Helper()
	label, rest, ok := strings.Cut(header, "=:")
	if !ok {
		t.Fatalf("unexpected signature header: %s", header)
	}
	encoded := strings.TrimSuffix(rest, ":")
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}
	raw[0] ^= 0xff
	return label + "=:" + base64.StdEncoding.EncodeToString(raw) + ":"
}

func TestProxyAuthorityMismatch(t *testing.T) {
	h := newHarness(t, proxyPolicy, func(h *Handler) { h.DebugHeaders = true })
	req := wba.NewRequest("GET", "https", "public.example", "/docs/intro", "")
	req.AddHeader("signature-agent", `"`+testOrigin+`"`)
	fields, err := wba.Sign(req, wba.SignOptions{
		PrivateKey: h.priv, Keyid: h.keyid, SignatureAgent: testOrigin,
		Created: testNow, Expires: testNow + 60,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	headers := http.Header{}
	headers.Set("signature-agent", `"`+testOrigin+`"`)
	headers.Set("signature-input", fields.SignatureInput)
	headers.Set("signature", fields.Signature)

	res := h.do(t, "GET", "/docs/intro", headers)
	if got := res.Header.Get("x-badge-reason"); got != "signature_invalid" {
		t.Errorf("reason = %q, want signature_invalid", got)
	}
}

func TestProxyTrustsForwardedHostWhenTold(t *testing.T) {
	h := newHarness(t, proxyPolicy, func(h *Handler) {
		h.Authority = AuthoritySource{Mode: "forwarded"}
		h.Scheme = SchemeSource{Mode: "forwarded"}
		h.DebugHeaders = true
	})
	req := wba.NewRequest("GET", "https", "public.example", "/docs/intro", "")
	req.AddHeader("signature-agent", `"`+testOrigin+`"`)
	fields, err := wba.Sign(req, wba.SignOptions{
		PrivateKey: h.priv, Keyid: h.keyid, SignatureAgent: testOrigin,
		Created: testNow, Expires: testNow + 60,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	headers := http.Header{}
	headers.Set("signature-agent", `"`+testOrigin+`"`)
	headers.Set("signature-input", fields.SignatureInput)
	headers.Set("signature", fields.Signature)
	headers.Set("x-forwarded-host", "public.example")
	headers.Set("x-forwarded-proto", "https")

	res := h.do(t, "GET", "/docs/intro", headers)
	if got := res.Header.Get("x-badge-reason"); got != "ok" {
		t.Errorf("reason = %q, want ok", got)
	}
	if res.StatusCode != 200 {
		t.Errorf("status = %d", res.StatusCode)
	}
}

// Forwarding headers are attacker-controlled unless something the operator runs
// strips them, so they are ignored by default.
func TestProxyIgnoresForwardedHostByDefault(t *testing.T) {
	h := newHarness(t, proxyPolicy, func(h *Handler) { h.DebugHeaders = true })
	headers := h.sign(t, "GET", "/docs/intro", wba.SignOptions{})
	headers.Set("x-forwarded-host", "attacker.example")
	res := h.do(t, "GET", "/docs/intro", headers)
	if got := res.Header.Get("x-badge-reason"); got != "ok" {
		t.Errorf("reason = %q; a spoofed forwarding header changed the authority", got)
	}
}

func TestProxyDryRunRefusesNothing(t *testing.T) {
	strict := "version: 1\ndefault: log-only\nrules:\n  - id: block-all-agents\n    action: deny\n    when: { status: verified }\n"
	h := newHarness(t, strict, func(h *Handler) { h.DryRun = true })

	res := h.do(t, "GET", "/docs/intro", h.sign(t, "GET", "/docs/intro", wba.SignOptions{}))
	if res.StatusCode != 200 {
		t.Fatalf("dry run refused a request: status %d", res.StatusCode)
	}
	record := h.sink.records[len(h.sink.records)-1]
	if record.Action != "log-only" || record.WouldAction != "deny" {
		t.Errorf("record = %+v", record)
	}
	if record.Rule != "block-all-agents" {
		t.Errorf("rule = %q", record.Rule)
	}
}

func TestProxyDebugHeadersOffByDefault(t *testing.T) {
	h := newHarness(t, proxyPolicy, nil)
	res := h.do(t, "GET", "/docs/intro", h.sign(t, "GET", "/docs/intro", wba.SignOptions{}))
	// In production these hand an attacker a policy oracle.
	if got := res.Header.Get("x-badge-reason"); got != "" {
		t.Errorf("x-badge-reason leaked by default: %q", got)
	}
}

// The record's field list is the privacy boundary: there is nowhere to put a
// signature, a header or a body.
func TestRecordCarriesNoSecrets(t *testing.T) {
	h := newHarness(t, proxyPolicy, nil)
	h.do(t, "GET", "/docs/intro", h.sign(t, "GET", "/docs/intro", wba.SignOptions{}))

	var buf bytes.Buffer
	JSONSink{Out: &buf}.Record(h.sink.records[len(h.sink.records)-1])
	serialized := buf.String()
	if strings.Contains(serialized, "signature-input") || strings.Contains(serialized, "sig1=") {
		t.Errorf("record leaked signature material: %s", serialized)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("record is not valid JSON: %v", err)
	}
}

func TestUpstreamFailureIsNotABadgeDecision(t *testing.T) {
	h := newHarness(t, proxyPolicy, nil)
	h.upstream.Close()
	res := h.do(t, "GET", "/docs/intro", nil)
	if res.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", res.StatusCode)
	}
}

func TestParseAuthorityAndScheme(t *testing.T) {
	if got, err := parseAuthority("fixed:public.example"); err != nil || got.Fixed != "public.example" {
		t.Errorf("parseAuthority = %+v %v", got, err)
	}
	if _, err := parseAuthority("nonsense"); err == nil {
		t.Error("parseAuthority should reject an unknown mode")
	}
	if _, err := parseScheme("gopher"); err == nil {
		t.Error("parseScheme should reject an unknown mode")
	}
}
