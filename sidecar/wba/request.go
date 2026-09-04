package wba

import (
	"net/http"
	"strings"
)

// Request is an HTTP request stripped of framework specifics.
type Request struct {
	Method string
	Scheme string
	// Authority is host[:port] as the client addressed it.
	//
	// The single most common source of a false signature_invalid: the signer
	// signed the authority it dialled, so if a load balancer rewrites Host,
	// every signature fails and the failure looks cryptographic.
	Authority string
	// Path is raw, not percent-decoded.
	Path string
	// Query is raw, without the leading "?".
	Query string

	values map[string][]string
}

func NewRequest(method, scheme, authority, path, query string) *Request {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return &Request{
		Method:    method,
		Scheme:    scheme,
		Authority: authority,
		Path:      path,
		Query:     query,
		values:    map[string][]string{},
	}
}

// AddHeader records one field occurrence, preserving order.
func (r *Request) AddHeader(name, value string) {
	key := strings.ToLower(name)
	r.values[key] = append(r.values[key], value)
}

// Header returns repeated fields joined with ", " in the order received, per
// RFC 9421 section 2.1.
func (r *Request) Header(name string) (string, bool) {
	values, ok := r.values[strings.ToLower(name)]
	if !ok || len(values) == 0 {
		return "", false
	}
	return strings.Join(values, ", "), true
}

// HeaderValues returns the individual occurrences, which the ;bs component
// parameter needs because a field value may legitimately contain a comma.
func (r *Request) HeaderValues(name string) ([]string, bool) {
	values, ok := r.values[strings.ToLower(name)]
	if !ok || len(values) == 0 {
		return nil, false
	}
	return values, true
}

// FromHTTP builds a Request from a net/http request.
//
// Authority resolution is the caller's decision, because trusting Forwarded or
// X-Forwarded-Host is only safe when something the operator controls strips
// those headers from client requests.
func FromHTTP(req *http.Request, scheme, authority string) *Request {
	query := req.URL.RawQuery
	out := NewRequest(req.Method, scheme, authority, req.URL.EscapedPath(), query)
	for name, values := range req.Header {
		for _, value := range values {
			out.AddHeader(name, value)
		}
	}
	return out
}
