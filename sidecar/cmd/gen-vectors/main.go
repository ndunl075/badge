// Command gen-vectors writes spec-vectors/go-signed.json.
//
// The signatures are produced by the Go implementation and verified by the
// TypeScript one and by the Cloudflare reference implementation, so the three
// agree on real bytes rather than only on a shared reading of the prose.
//
// The key is RFC 8037 Appendix A.1 and Ed25519 is deterministic, so
// regenerating produces byte-identical output unless behaviour actually
// changed. That makes a diff in the fixture a signal rather than noise.
//
//	go run ./cmd/gen-vectors
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ndunl075/badge/sidecar/wba"
)

const (
	now    = int64(1735689600)
	origin = "https://agent.example"
	// RFC 8037 Appendix A.1.
	seedB64 = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	xB64    = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)

type vector struct {
	Name    string            `json:"name"`
	Request requestJSON       `json:"request"`
	Headers map[string]string `json:"headers"`
	Base    string            `json:"base"`
}

type requestJSON struct {
	Method    string `json:"method"`
	Scheme    string `json:"scheme"`
	Authority string `json:"authority"`
	Path      string `json:"path"`
	Query     string `json:"query"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-vectors:", err)
		os.Exit(1)
	}
}

func run() error {
	seed, err := base64.RawURLEncoding.DecodeString(seedB64)
	if err != nil {
		return err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	publicJWK := wba.JWK{Kty: "OKP", Crv: "Ed25519", X: xB64}

	// Confirm the published private and public halves actually correspond,
	// rather than trusting that they were transcribed correctly.
	derived := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if derived != xB64 {
		return fmt.Errorf("seed does not match the published public key: %s", derived)
	}
	keyid, err := wba.Thumbprint(publicJWK)
	if err != nil {
		return err
	}

	cases := []struct {
		name       string
		request    requestJSON
		components []string
	}{
		{
			name:    "the web-bot-auth minimum covered set",
			request: requestJSON{"GET", "https", "example.com", "/docs/intro", ""},
		},
		{
			name:       "signing @target-uri instead of @authority",
			request:    requestJSON{"GET", "https", "example.com", "/docs/intro", "a=1"},
			components: []string{`"@target-uri"`, `"signature-agent"`},
		},
		{
			name:    "a POST with a query string",
			request: requestJSON{"POST", "https", "example.com", "/checkout/pay", "cart=abc&ref=x%20y"},
			components: []string{
				`"@method"`, `"@authority"`, `"@path"`, `"@query"`, `"signature-agent"`,
			},
		},
		{
			name:       "a non-standard method, preserved exactly",
			request:    requestJSON{"foo", "https", "example.com", "/", ""},
			components: []string{`"@method"`, `"@authority"`, `"signature-agent"`},
		},
	}

	vectors := make([]vector, 0, len(cases))
	for _, c := range cases {
		req := wba.NewRequest(c.request.Method, c.request.Scheme, c.request.Authority, c.request.Path, c.request.Query)
		req.AddHeader("signature-agent", `"`+origin+`"`)

		fields, err := wba.Sign(req, wba.SignOptions{
			PrivateKey: priv, Keyid: keyid, SignatureAgent: origin,
			Created: now, Expires: now + 60, Components: c.components,
		})
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		vectors = append(vectors, vector{
			Name:    c.name,
			Request: c.request,
			Headers: map[string]string{
				"signature-agent": `"` + origin + `"`,
				"signature-input": fields.SignatureInput,
				"signature":       fields.Signature,
			},
			Base: fields.Base,
		})
	}

	doc := map[string]any{
		"description": "Requests signed by the Go implementation, for the TypeScript one and the " +
			"Cloudflare reference implementation to verify. The key is RFC 8037 Appendix A.1 and " +
			"Ed25519 is deterministic, so these bytes are stable. Regenerate with " +
			"`go run ./cmd/gen-vectors` from sidecar/.",
		"profile":              wba.DefaultProfile.ID,
		"now":                  now,
		"signatureAgentOrigin": origin,
		"keyid":                keyid,
		"publishedKeys":        []wba.JWK{publicJWK},
		"vectors":              vectors,
	}

	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	out := filepath.Join("..", "spec-vectors", "go-signed.json")
	if err := os.WriteFile(out, append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d vectors to %s\n", len(vectors), out)
	return nil
}
