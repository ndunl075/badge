package wba

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ndunl075/badge/sidecar/sfv"
)

// The signature base vectors in spec-vectors/ are written by hand rather than
// generated from either implementation, so they are an independent statement of
// what the bytes must be. This is what they were written for: a second
// implementation reproducing them exactly.
//
// A disagreement here means one of the three — this port, the TypeScript, or
// the vector — is wrong, and the other two say which.

type baseVector struct {
	Name    string `json:"name"`
	Request struct {
		Method    string                     `json:"method"`
		Scheme    string                     `json:"scheme"`
		Authority string                     `json:"authority"`
		Path      string                     `json:"path"`
		Query     string                     `json:"query"`
		Headers   map[string]json.RawMessage `json:"headers"`
	} `json:"request"`
	Components      []string `json:"components"`
	SignatureParams string   `json:"signatureParams"`
	Base            string   `json:"base"`
}

func loadBaseVectors(t *testing.T) []baseVector {
	t.Helper()
	raw, err := os.ReadFile("../../spec-vectors/signature-base.json")
	if err != nil {
		t.Fatalf("reading vectors: %v", err)
	}
	var doc struct {
		Vectors []baseVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing vectors: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	return doc.Vectors
}

func requestFromVector(t *testing.T, v baseVector) *Request {
	t.Helper()
	req := NewRequest(v.Request.Method, v.Request.Scheme, v.Request.Authority, v.Request.Path, v.Request.Query)
	for name, raw := range v.Request.Headers {
		var single string
		if err := json.Unmarshal(raw, &single); err == nil {
			req.AddHeader(name, single)
			continue
		}
		var many []string
		if err := json.Unmarshal(raw, &many); err != nil {
			t.Fatalf("header %s is neither a string nor a list", name)
		}
		for _, value := range many {
			req.AddHeader(name, value)
		}
	}
	return req
}

func TestSignatureBaseVectors(t *testing.T) {
	for _, v := range loadBaseVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			req := requestFromVector(t, v)
			components := make([]sfv.Item, 0, len(v.Components))
			for _, id := range v.Components {
				item, err := sfv.ParseItem(id)
				if err != nil {
					t.Fatalf("parsing component %q: %v", id, err)
				}
				components = append(components, item)
			}

			base, err := BuildBase(req, components, v.SignatureParams, nil)
			if err != nil {
				t.Fatalf("BuildBase: %v", err)
			}
			if base != v.Base {
				t.Errorf("base mismatch\n got: %q\nwant: %q", base, v.Base)
			}
		})
	}
}

func TestSignatureBaseHasNoTrailingNewline(t *testing.T) {
	for _, v := range loadBaseVectors(t) {
		if strings.HasSuffix(v.Base, "\n") {
			t.Errorf("%s: vector base ends with a newline", v.Name)
		}
	}
}
