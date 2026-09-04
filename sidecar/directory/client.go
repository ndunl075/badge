package directory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// FailureKind classifies a transport failure so the resolver can map it to a
// reason code.
type FailureKind string

const (
	FailureTimeout  FailureKind = "timeout"
	FailureTooLarge FailureKind = "too-large"
	FailureBlocked  FailureKind = "blocked"
	FailureNetwork  FailureKind = "network"
)

// ClientError carries the kind of transport failure that occurred.
type ClientError struct {
	Message string
	Kind    FailureKind
}

func (e *ClientError) Error() string { return e.Message }

// Response is a fetched directory response.
type Response struct {
	Status  int
	Headers http.Header
	Body    []byte
}

// Fetcher performs a guarded GET.
type Fetcher interface {
	Get(ctx context.Context, url string, timeout time.Duration, maxBytes int64, accept string) (*Response, error)
}

// ClientOptions configures the guarded HTTP client.
type ClientOptions struct {
	// AllowPrivateAddresses permits connections to loopback, private and
	// link-local addresses.
	//
	// Off by default and it should stay off. It removes the guard that stops an
	// attacker-supplied Signature-Agent from pointing the proxy at a cloud
	// metadata endpoint or an internal admin panel.
	AllowPrivateAddresses bool
	// AllowHTTP permits plain http. Off by default: a directory fetched over
	// http can be rewritten in flight and the attacker substitutes their key.
	AllowHTTP bool
}

// HTTPFetcher is the default transport: https only, no redirects, a public
// address check on the socket itself, a hard timeout and a body cap.
type HTTPFetcher struct {
	options ClientOptions
	client  *http.Client
}

// NewHTTPFetcher builds a fetcher whose dialer refuses non-public addresses.
//
// The check runs in the dialer's Control hook, which receives the address the
// socket is about to connect to. That closes the window a resolve-then-connect
// check leaves open: there is nothing for DNS to be rebound to in between,
// because this is the connection.
func NewHTTPFetcher(options ClientOptions) *HTTPFetcher {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			if options.AllowPrivateAddresses {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return &ClientError{Message: "unparseable dial address", Kind: FailureBlocked}
			}
			addr, err := netip.ParseAddr(host)
			if err != nil || !IsPublicAddress(addr) {
				return &ClientError{
					Message: fmt.Sprintf("refusing to connect to a non-public address: %s", host),
					Kind:    FailureBlocked,
				}
			}
			return nil
		},
	}

	return &HTTPFetcher{
		options: options,
		client: &http.Client{
			Transport: &http.Transport{
				DialContext:           dialer.DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          32,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   5 * time.Second,
				ExpectContinueTimeout: time.Second,
				DisableCompression:    true,
			},
			// Redirects are never followed. A 302 to the metadata endpoint is
			// the obvious way around an origin check, and the directory lives at
			// a fixed path on the origin the caller named, so there is nowhere
			// legitimate to redirect to.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (f *HTTPFetcher) Get(
	ctx context.Context, rawURL string, timeout time.Duration, maxBytes int64, accept string,
) (*Response, error) {
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil, &ClientError{Message: "not a valid URL: " + rawURL, Kind: FailureBlocked}
	}
	if target.Scheme != "https" && !(f.options.AllowHTTP && target.Scheme == "http") {
		return nil, &ClientError{
			Message: "refusing to fetch a non-https directory: " + rawURL,
			Kind:    FailureBlocked,
		}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, &ClientError{Message: err.Error(), Kind: FailureBlocked}
	}
	req.Header.Set("accept", accept)
	req.Header.Set("accept-encoding", "identity")

	res, err := f.client.Do(req)
	if err != nil {
		return nil, classify(err, ctx)
	}
	defer res.Body.Close()

	// A declared Content-Length over the cap is refused before a single byte of
	// body is read.
	if res.ContentLength > maxBytes {
		return nil, &ClientError{Message: "directory declares a body over the size cap", Kind: FailureTooLarge}
	}

	// Read one byte past the cap so an oversized body is detected rather than
	// silently truncated into a valid-looking JWKS.
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil {
		return nil, classify(err, ctx)
	}
	if int64(len(body)) > maxBytes {
		return nil, &ClientError{Message: "directory body exceeded the size cap", Kind: FailureTooLarge}
	}

	return &Response{Status: res.StatusCode, Headers: res.Header, Body: body}, nil
}

func classify(err error, ctx context.Context) *ClientError {
	var clientErr *ClientError
	if errors.As(err, &clientErr) {
		return clientErr
	}
	if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
		return &ClientError{Message: err.Error(), Kind: FailureTimeout}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &ClientError{Message: err.Error(), Kind: FailureTimeout}
	}
	return &ClientError{Message: err.Error(), Kind: FailureNetwork}
}
