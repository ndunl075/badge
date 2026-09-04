package wba

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// The Go-signed vectors are committed so the TypeScript implementation and the
// Cloudflare reference implementation can verify them. This side checks that
// the committed file still matches what this code produces and accepts, so a
// change in signing that nobody regenerated shows up here first.

type goSignedDoc struct {
	Now                  int64  `json:"now"`
	Profile              string `json:"profile"`
	SignatureAgentOrigin string `json:"signatureAgentOrigin"`
	Keyid                string `json:"keyid"`
	PublishedKeys        []JWK  `json:"publishedKeys"`
	Vectors              []struct {
		Name    string `json:"name"`
		Request struct {
			Method    string `json:"method"`
			Scheme    string `json:"scheme"`
			Authority string `json:"authority"`
			Path      string `json:"path"`
			Query     string `json:"query"`
		} `json:"request"`
		Headers map[string]string `json:"headers"`
		Base    string            `json:"base"`
	} `json:"vectors"`
}

func TestGoSignedVectorsVerify(t *testing.T) {
	raw, err := os.ReadFile("../../spec-vectors/go-signed.json")
	if err != nil {
		t.Fatalf("reading vectors: %v", err)
	}
	var doc goSignedDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing vectors: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}

	verifier := NewVerifier(StaticKeys{doc.SignatureAgentOrigin: doc.PublishedKeys})
	verifier.Clock = NewFixedClock(doc.Now)

	for _, vector := range doc.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			req := NewRequest(
				vector.Request.Method, vector.Request.Scheme,
				vector.Request.Authority, vector.Request.Path, vector.Request.Query,
			)
			for name, value := range vector.Headers {
				req.AddHeader(name, value)
			}
			got := verifier.Verify(context.Background(), req)
			if got.Reason != ReasonOK {
				t.Errorf("reason = %q, want ok", got.Reason)
			}
			if got.Keyid != doc.Keyid {
				t.Errorf("keyid = %q, want %q", got.Keyid, doc.Keyid)
			}
		})
	}
}
