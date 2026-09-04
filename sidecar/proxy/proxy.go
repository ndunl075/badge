// Package proxy runs the Badge doorman in front of an upstream origin.
package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/ndunl075/badge/sidecar/policy"
	"github.com/ndunl075/badge/sidecar/wba"
)

// Record is one structured decision record.
//
// The field list is the privacy boundary, enforced by construction rather than
// by a redaction pass: there is nowhere to put a signature, a header or a body,
// so none can be logged by accident.
type Record struct {
	TS             string `json:"ts"`
	Status         string `json:"status"`
	Class          string `json:"class"`
	Reason         string `json:"reason"`
	Action         string `json:"action"`
	Rule           string `json:"rule"`
	Profile        string `json:"profile"`
	Route          string `json:"route"`
	Authority      string `json:"authority"`
	SignatureAgent string `json:"signature_agent,omitempty"`
	Keyid          string `json:"keyid,omitempty"`
	Operator       string `json:"operator,omitempty"`
	Cache          string `json:"cache,omitempty"`
	TotalUs        int64  `json:"total_us"`
	DirectoryUs    int64  `json:"directory_us,omitempty"`
	// WouldAction is present only in dry run: what the policy would have done.
	WouldAction string `json:"would_action,omitempty"`
}

// Sink receives decision records. It must not block: a sink that can hold up a
// response is the least important thing on this path behaving like the most.
type Sink interface{ Record(Record) }

// JSONSink writes one JSON object per line.
type JSONSink struct{ Out io.Writer }

func (s JSONSink) Record(r Record) {
	encoded, err := json.Marshal(r)
	if err != nil {
		return
	}
	fmt.Fprintln(s.Out, string(encoded))
}

// Handler verifies, applies the policy, records the decision and forwards.
type Handler struct {
	Verifier *wba.Verifier
	Policy   *policy.Engine
	Upstream http.Handler
	Sink     Sink

	// Authority chooses what the proxy believes the client addressed. Trusting
	// forwarding headers is only safe when something the operator controls
	// strips them from client requests.
	Authority AuthoritySource
	Scheme    SchemeSource

	DryRun       bool
	DenyStatus   int
	DenyBody     string
	DebugHeaders bool
}

// AuthoritySource says where the authority comes from.
type AuthoritySource struct {
	Mode  string // "host", "forwarded" or "fixed"
	Fixed string
}

// SchemeSource says where the scheme comes from.
type SchemeSource struct{ Mode string } // "auto", "http", "https", "forwarded"

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scheme := h.resolveScheme(r)
	authority := h.resolveAuthority(r)
	verdict := h.Verifier.Verify(r.Context(), wba.FromHTTP(r, scheme, authority))
	decision := h.Policy.Evaluate(verdict, r.Method, r.URL.EscapedPath())

	effective := decision
	would := ""
	if h.DryRun {
		would = string(decision.Action)
		effective.Action = policy.ActionLogOnly
	}
	h.record(effective, verdict, r, authority, would)

	if h.DebugHeaders {
		w.Header().Set("x-badge-status", string(verdict.Status))
		w.Header().Set("x-badge-reason", string(verdict.Reason))
		w.Header().Set("x-badge-rule", decision.RuleID)
	}

	if effective.Action == policy.ActionDeny {
		status := h.DenyStatus
		if status == 0 {
			status = http.StatusForbidden
		}
		body := h.DenyBody
		if body == "" {
			body = "Forbidden"
		}
		// A denial is specific to this caller's credentials and must never be
		// stored by a shared cache in front of the origin.
		w.Header().Set("cache-control", "no-store")
		w.Header().Set("content-type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		io.WriteString(w, body)
		return
	}

	h.Upstream.ServeHTTP(w, r)
}

func (h *Handler) record(d policy.Decision, v wba.Verdict, r *http.Request, authority, would string) {
	if h.Sink == nil {
		return
	}
	h.Sink.Record(Record{
		TS:             time.Now().UTC().Format(time.RFC3339),
		Status:         string(v.Status),
		Class:          string(v.Class),
		Reason:         string(v.Reason),
		Action:         string(d.Action),
		Rule:           d.RuleID,
		Profile:        v.Profile,
		Route:          r.Method + " " + r.URL.EscapedPath(),
		Authority:      authority,
		SignatureAgent: v.SignatureAgent,
		Keyid:          v.Keyid,
		Operator:       d.Operator,
		Cache:          v.Cache,
		TotalUs:        v.TotalUs,
		DirectoryUs:    v.DirectoryUs,
		WouldAction:    would,
	})
}

func (h *Handler) resolveAuthority(r *http.Request) string {
	switch h.Authority.Mode {
	case "fixed":
		return h.Authority.Fixed
	case "forwarded":
		if host := forwardedParam(r.Header.Get("forwarded"), "host"); host != "" {
			return host
		}
		if host := firstValue(r.Header.Get("x-forwarded-host")); host != "" {
			return host
		}
	}
	return r.Host
}

func (h *Handler) resolveScheme(r *http.Request) string {
	switch h.Scheme.Mode {
	case "http", "https":
		return h.Scheme.Mode
	case "forwarded":
		proto := forwardedParam(r.Header.Get("forwarded"), "proto")
		if proto == "" {
			proto = firstValue(r.Header.Get("x-forwarded-proto"))
		}
		if proto == "http" || proto == "https" {
			return proto
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// forwardedParam reads one parameter from the first element of an RFC 7239
// Forwarded header. Only the first element matters: it is the hop closest to
// the client.
func forwardedParam(value, name string) string {
	if value == "" {
		return ""
	}
	element := strings.Split(value, ",")[0]
	for _, pair := range strings.Split(element, ";") {
		key, raw, ok := strings.Cut(pair, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), name) {
			continue
		}
		raw = strings.TrimSpace(raw)
		return strings.Trim(raw, `"`)
	}
	return ""
}

func firstValue(value string) string {
	if value == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(value, ",")[0])
}

// NewUpstream builds a reverse proxy to the configured origin.
func NewUpstream(target string) (http.Handler, error) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("upstream must be an absolute URL, got %q", target)
	}
	rp := httputil.NewSingleHostReverseProxy(parsed)
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		// An upstream failure is the origin's problem, not the caller's, and
		// must not be reported as a Badge decision.
		w.Header().Set("cache-control", "no-store")
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "upstream unavailable")
	}
	return rp, nil
}
