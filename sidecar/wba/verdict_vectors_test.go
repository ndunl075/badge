package wba

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// The verdict vectors are signed with the fixed RFC 8037 Appendix A.1 key and
// committed, so replaying them here checks far more than the base: the reason
// code table, the status and class mapping, the ordering of the preflight
// checks, and the signature check itself.
//
// Reason codes are duplicated across the two implementations rather than
// shared, which is a real cost. This is what catches the drift.

type verdictVector struct {
	Name    string `json:"name"`
	Request struct {
		Method    string            `json:"method"`
		Scheme    string            `json:"scheme"`
		Authority string            `json:"authority"`
		Path      string            `json:"path"`
		Query     string            `json:"query"`
		Headers   map[string]string `json:"headers"`
	} `json:"request"`
	Expect struct {
		Status string `json:"status"`
		Class  string `json:"class"`
		Reason string `json:"reason"`
	} `json:"expect"`
}

type verdictDoc struct {
	Now                  int64           `json:"now"`
	Profile              string          `json:"profile"`
	SignatureAgentOrigin string          `json:"signatureAgentOrigin"`
	PublishedKeys        []JWK           `json:"publishedKeys"`
	UnrelatedKey         JWK             `json:"unrelatedKey"`
	Vectors              []verdictVector `json:"vectors"`
}

func loadVerdictVectors(t *testing.T) verdictDoc {
	t.Helper()
	raw, err := os.ReadFile("../../spec-vectors/verdicts.json")
	if err != nil {
		t.Fatalf("reading vectors: %v", err)
	}
	var doc verdictDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing vectors: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	return doc
}

func verifierFor(doc verdictDoc, keys []JWK) *Verifier {
	v := NewVerifier(StaticKeys{doc.SignatureAgentOrigin: keys})
	v.Clock = NewFixedClock(doc.Now)
	return v
}

func TestVerdictVectors(t *testing.T) {
	doc := loadVerdictVectors(t)
	verifier := verifierFor(doc, doc.PublishedKeys)

	for _, vector := range doc.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			req := NewRequest(
				vector.Request.Method, vector.Request.Scheme,
				vector.Request.Authority, vector.Request.Path, vector.Request.Query,
			)
			for name, value := range vector.Request.Headers {
				req.AddHeader(name, value)
			}

			got := verifier.Verify(context.Background(), req)
			if string(got.Reason) != vector.Expect.Reason {
				t.Errorf("reason = %q, want %q", got.Reason, vector.Expect.Reason)
			}
			if string(got.Status) != vector.Expect.Status {
				t.Errorf("status = %q, want %q", got.Status, vector.Expect.Status)
			}
			if string(got.Class) != vector.Expect.Class {
				t.Errorf("class = %q, want %q", got.Class, vector.Expect.Class)
			}
			if got.Profile != doc.Profile {
				t.Errorf("profile = %q, want %q", got.Profile, doc.Profile)
			}
		})
	}
}

func TestVerdictVectorsUnrelatedKey(t *testing.T) {
	doc := loadVerdictVectors(t)
	verifier := verifierFor(doc, []JWK{doc.UnrelatedKey})

	for _, vector := range doc.Vectors {
		if vector.Expect.Reason != "ok" {
			continue
		}
		req := NewRequest(
			vector.Request.Method, vector.Request.Scheme,
			vector.Request.Authority, vector.Request.Path, vector.Request.Query,
		)
		for name, value := range vector.Request.Headers {
			req.AddHeader(name, value)
		}
		if got := verifier.Verify(context.Background(), req); got.Reason != ReasonKeyNotFound {
			t.Errorf("%s: reason = %q, want key_not_found", vector.Name, got.Reason)
		}
	}
}

// The published RFC 8037 Appendix A.3 vector, which both implementations and
// the RFC itself must agree on.
func TestThumbprintRFC8037(t *testing.T) {
	key := JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	got, err := Thumbprint(key)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if want := "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"; got != want {
		t.Errorf("thumbprint = %q, want %q", got, want)
	}
}

func TestCanonicalJSONShape(t *testing.T) {
	key := JWK{Kty: "OKP", Crv: "Ed25519", X: "abc", Kid: "ignored", Alg: "Ed25519"}
	got, err := CanonicalJSON(key)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if want := `{"crv":"Ed25519","kty":"OKP","x":"abc"}`; got != want {
		t.Errorf("canonical = %q, want %q", got, want)
	}
}

// Every reason code the verifier can emit must classify consistently, or the
// two implementations disagree about whose fault a failure was.
func TestReasonClassInvariants(t *testing.T) {
	for _, reason := range AllReasons() {
		status, class := reason.Info()
		if (class == ClassOK) != (status == StatusVerified) {
			t.Errorf("%s: class ok and status verified must coincide", reason)
		}
		if (class == ClassOK) != (reason == ReasonOK) {
			t.Errorf("%s: only ok may carry class ok", reason)
		}
		if class == ClassAbsent && status != StatusUnknown {
			t.Errorf("%s: absent must be unknown", reason)
		}
		if class != ClassAbsent && class != ClassOK && status != StatusClaimed {
			t.Errorf("%s: every other failure must be claimed", reason)
		}
	}
}
