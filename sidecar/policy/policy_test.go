package policy

import (
	"strings"
	"testing"

	"github.com/ndunl075/badge/sidecar/wba"
)

const examplePolicy = `
version: 1
default: log-only
operators:
  example: ["https://agent.example"]
rules:
  - id: forgeries-are-hostile
    action: deny
    when: { class: untrusted }
  - id: our-outage-is-not-their-fault
    action: log-only
    when: { class: unverifiable }
  - id: docs-open-to-known-agents
    action: allow
    when: { status: verified, operator: example }
    routes: ["GET /docs/**"]
  - id: no-agents-at-checkout
    action: deny
    when: { class: [ok, untrusted, malformed, expired] }
    routes: ["POST /checkout/**"]
`

func engineFor(t *testing.T, source string) *Engine {
	t.Helper()
	parsed, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	engine, err := Compile(*parsed)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return engine
}

func verdictFor(reason wba.Reason, agent string) wba.Verdict {
	status, class := reason.Info()
	return wba.Verdict{Status: status, Class: class, Reason: reason, SignatureAgent: agent}
}

func TestRouteMatching(t *testing.T) {
	cases := []struct {
		pattern, method, path string
		want                  bool
	}{
		{"GET /docs", "GET", "/docs", true},
		{"GET /docs", "POST", "/docs", false},
		{"get /docs", "GET", "/docs", true},
		{"GET|HEAD /docs", "HEAD", "/docs", true},
		{"GET|HEAD /docs", "POST", "/docs", false},
		{"/docs", "DELETE", "/docs", true},
		{"* /docs", "DELETE", "/docs", true},
		{"/docs/*", "GET", "/docs/intro", true},
		{"/docs/*", "GET", "/docs/a/b", false},
		{"/docs/**", "GET", "/docs/a/b", true},
		// The behaviour people assume, and the one that quietly leaves a hole.
		{"/docs/**", "GET", "/docs", true},
		{"/docs/**", "GET", "/docs/", true},
		{"/docs/**", "GET", "/docsy", false},
		{"/v?/x", "GET", "/v1/x", true},
		{"/v?/x", "GET", "/v12/x", false},
		{"/a.b", "GET", "/a.b", true},
		{"/a.b", "GET", "/axb", false},
		{"/docs", "GET", "/docs/extra", false},
		{"/docs", "GET", "/prefix/docs", false},
	}
	for _, tc := range cases {
		route, err := CompileRoute(tc.pattern)
		if err != nil {
			t.Fatalf("CompileRoute(%q): %v", tc.pattern, err)
		}
		if got := route.Matches(tc.method, tc.path); got != tc.want {
			t.Errorf("%q matches %s %s = %v, want %v", tc.pattern, tc.method, tc.path, got, tc.want)
		}
	}
}

func TestCompileRouteRejects(t *testing.T) {
	for _, pattern := range []string{"   ", "GET docs", "GE:T /docs"} {
		if _, err := CompileRoute(pattern); err == nil {
			t.Errorf("CompileRoute(%q) should have failed", pattern)
		}
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"missing version":     "default: log-only\n",
		"wrong version":       "version: 2\ndefault: log-only\n",
		"missing default":     "version: 1\n",
		"misspelled action":   "version: 1\ndefault: log_only\n",
		"unknown rule key":    "version: 1\ndefault: log-only\nrules:\n  - id: r\n    action: deny\n    unless: {}\n",
		"unknown status":      "version: 1\ndefault: log-only\nrules:\n  - id: r\n    action: deny\n    when: { status: sketchy }\n",
		"unknown reason":      "version: 1\ndefault: log-only\nrules:\n  - id: r\n    action: deny\n    when: { reason: nope }\n",
		"empty condition":     "version: 1\ndefault: log-only\nrules:\n  - id: r\n    action: deny\n    when: {}\n",
		"missing id":          "version: 1\ndefault: log-only\nrules:\n  - action: deny\n",
		"duplicate ids":       "version: 1\ndefault: log-only\nrules:\n  - id: r\n    action: deny\n  - id: r\n    action: allow\n",
		"unknown operator":    "version: 1\ndefault: log-only\nrules:\n  - id: r\n    action: allow\n    when: { operator: ghost }\n",
		"bad route":           "version: 1\ndefault: log-only\nrules:\n  - id: r\n    action: deny\n    when: { class: untrusted }\n    routes: [docs]\n",
		"origin with a slash": "version: 1\ndefault: log-only\noperators:\n  a: [\"https://agent.example/\"]\n",
		"http origin":         "version: 1\ndefault: log-only\noperators:\n  a: [\"http://agent.example\"]\n",
	}
	for name, source := range cases {
		if _, err := Parse([]byte(source)); err == nil {
			t.Errorf("%s: Parse should have failed", name)
		}
	}
}

func TestParseAcceptsJSON(t *testing.T) {
	// YAML is a superset of JSON, so one parser handles both.
	const source = `{"version":1,"default":"log-only","rules":[{"id":"r","action":"deny","when":{"class":"untrusted"}}]}`
	parsed, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.Rules) != 1 {
		t.Errorf("rules = %d", len(parsed.Rules))
	}
}

func TestParseNormalizesScalarToList(t *testing.T) {
	parsed, err := Parse([]byte("version: 1\ndefault: log-only\nrules:\n  - id: r\n    action: deny\n    when: { class: untrusted }\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := parsed.Rules[0].When.Class; len(got) != 1 || got[0] != "untrusted" {
		t.Errorf("class = %v", got)
	}
}

func TestEvaluateDefaults(t *testing.T) {
	engine, err := Compile(DefaultPolicy)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// Installing the proxy cannot break a live site.
	for _, reason := range []wba.Reason{wba.ReasonOK, wba.ReasonSignatureInvalid, wba.ReasonDirectoryTimeout, wba.ReasonNoSignatureFields} {
		got := engine.Evaluate(verdictFor(reason, ""), "GET", "/")
		if got.Action != ActionLogOnly || got.RuleID != "default" {
			t.Errorf("%s -> %+v", reason, got)
		}
	}
}

func TestEvaluateFirstMatchWins(t *testing.T) {
	engine := engineFor(t, "version: 1\ndefault: log-only\nrules:\n"+
		"  - id: first\n    action: allow\n    when: { class: untrusted }\n"+
		"  - id: second\n    action: deny\n    when: { class: untrusted }\n")
	if got := engine.Evaluate(verdictFor(wba.ReasonSignatureInvalid, ""), "GET", "/"); got.RuleID != "first" {
		t.Errorf("rule = %q", got.RuleID)
	}
}

// The two rules the architecture argues hardest for.
func TestForgeryAndOutageDiverge(t *testing.T) {
	engine := engineFor(t, examplePolicy)
	forged := engine.Evaluate(verdictFor(wba.ReasonSignatureInvalid, "https://agent.example"), "GET", "/docs/intro")
	outage := engine.Evaluate(verdictFor(wba.ReasonDirectoryTimeout, "https://agent.example"), "GET", "/docs/intro")
	if forged.Action != ActionDeny {
		t.Errorf("a forged signature should be denied, got %v", forged.Action)
	}
	if outage.Action != ActionLogOnly {
		t.Errorf("our own outage should not be denied, got %v", outage.Action)
	}
}

func TestEvaluateRoutesAndOperators(t *testing.T) {
	engine := engineFor(t, examplePolicy)
	verified := verdictFor(wba.ReasonOK, "https://agent.example")

	if got := engine.Evaluate(verified, "GET", "/docs/intro"); got.Action != ActionAllow || got.Operator != "example" {
		t.Errorf("docs = %+v", got)
	}
	if got := engine.Evaluate(verified, "GET", "/admin"); got.Action != ActionLogOnly {
		t.Errorf("admin = %+v", got)
	}
	if got := engine.Evaluate(verified, "POST", "/checkout/pay"); got.Action != ActionDeny {
		t.Errorf("checkout = %+v", got)
	}
	stranger := verdictFor(wba.ReasonOK, "https://stranger.example")
	if got := engine.Evaluate(stranger, "GET", "/docs/intro"); got.Operator != "" {
		t.Errorf("unknown origin should have no operator label, got %q", got.Operator)
	}
}

func TestConditionFieldsAreANDed(t *testing.T) {
	engine := engineFor(t, examplePolicy)
	// verified but from an origin with no operator label: the operator
	// condition fails, so the rule does not fire.
	got := engine.Evaluate(verdictFor(wba.ReasonOK, "https://other.example"), "GET", "/docs/intro")
	if got.RuleID != "default" {
		t.Errorf("rule = %q, want default", got.RuleID)
	}
}

func TestParseErrorMentionsLocation(t *testing.T) {
	_, err := Parse([]byte("version: 1\ndefault: log-only\nrules:\n  - id: r\n    action: nope\n"))
	if err == nil || !strings.Contains(err.Error(), "rules[0].action") {
		t.Errorf("error = %v, want a path into the document", err)
	}
}
