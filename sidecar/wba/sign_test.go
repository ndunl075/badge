package wba

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func testKeyPair(t *testing.T) (ed25519.PrivateKey, JWK, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk := JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
	keyid, err := Thumbprint(jwk)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return priv, jwk, keyid
}

func signedRequest(t *testing.T, priv ed25519.PrivateKey, keyid string, opts SignOptions) *Request {
	t.Helper()
	req := NewRequest("GET", "https", "example.com", "/docs/intro", "")
	if opts.SignatureAgent != "" {
		req.AddHeader("signature-agent", `"`+opts.SignatureAgent+`"`)
	}
	opts.PrivateKey = priv
	opts.Keyid = keyid
	fields, err := Sign(req, opts)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	req.AddHeader("signature-input", fields.SignatureInput)
	req.AddHeader("signature", fields.Signature)
	return req
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	priv, jwk, keyid := testKeyPair(t)
	const now = int64(1735689600)
	const origin = "https://agent.example"

	req := signedRequest(t, priv, keyid, SignOptions{
		Created: now, Expires: now + 60, SignatureAgent: origin,
	})

	verifier := NewVerifier(StaticKeys{origin: {jwk}})
	verifier.Clock = &FixedClock{Seconds: now}

	got := verifier.Verify(context.Background(), req)
	if got.Reason != ReasonOK {
		t.Fatalf("reason = %q, want ok", got.Reason)
	}
	if got.Keyid != keyid {
		t.Errorf("keyid = %q", got.Keyid)
	}
	if got.SignatureAgent != origin {
		t.Errorf("agent = %q", got.SignatureAgent)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	priv, jwk, keyid := testKeyPair(t)
	const now = int64(1735689600)
	const origin = "https://agent.example"

	req := signedRequest(t, priv, keyid, SignOptions{
		Created: now, Expires: now + 60, SignatureAgent: origin,
	})
	// Move the request to a different authority, leaving the signature intact.
	moved := NewRequest("GET", "https", "evil.example", "/docs/intro", "")
	for _, name := range []string{"signature-agent", "signature-input", "signature"} {
		if value, ok := req.Header(name); ok {
			moved.AddHeader(name, value)
		}
	}

	verifier := NewVerifier(StaticKeys{origin: {jwk}})
	verifier.Clock = &FixedClock{Seconds: now}
	if got := verifier.Verify(context.Background(), moved); got.Reason != ReasonSignatureInvalid {
		t.Errorf("reason = %q, want signature_invalid", got.Reason)
	}
}

func TestVerifyTargetURI(t *testing.T) {
	priv, jwk, keyid := testKeyPair(t)
	const now = int64(1735689600)
	const origin = "https://agent.example"

	req := signedRequest(t, priv, keyid, SignOptions{
		Created: now, Expires: now + 60, SignatureAgent: origin,
		Components: []string{`"@target-uri"`, `"signature-agent"`},
	})

	verifier := NewVerifier(StaticKeys{origin: {jwk}})
	verifier.Clock = &FixedClock{Seconds: now}
	// @target-uri contains the authority and pins more besides, so it satisfies
	// the requirement rather than failing it.
	if got := verifier.Verify(context.Background(), req); got.Reason != ReasonOK {
		t.Errorf("reason = %q, want ok", got.Reason)
	}
}

func TestReplayProtection(t *testing.T) {
	priv, jwk, keyid := testKeyPair(t)
	const now = int64(1735689600)
	const origin = "https://agent.example"
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	req := signedRequest(t, priv, keyid, SignOptions{
		Created: now, Expires: now + 60, SignatureAgent: origin, Nonce: nonce,
	})

	seen := map[string]bool{}
	verifier := NewVerifier(StaticKeys{origin: {jwk}})
	verifier.Clock = &FixedClock{Seconds: now}
	verifier.Replay = nonceStoreFunc(func(_ context.Context, nonce string, _ int64) (bool, error) {
		if seen[nonce] {
			return false, nil
		}
		seen[nonce] = true
		return true, nil
	})

	if got := verifier.Verify(context.Background(), req); got.Reason != ReasonOK {
		t.Fatalf("first = %q", got.Reason)
	}
	if got := verifier.Verify(context.Background(), req); got.Reason != ReasonReplayDetected {
		t.Errorf("second = %q, want replay_detected", got.Reason)
	}
}

type nonceStoreFunc func(context.Context, string, int64) (bool, error)

func (f nonceStoreFunc) CheckAndRecord(ctx context.Context, nonce string, expiresAt int64) (bool, error) {
	return f(ctx, nonce, expiresAt)
}
