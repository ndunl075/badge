package proxy

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ndunl075/badge/sidecar/directory"
	"github.com/ndunl075/badge/sidecar/policy"
	"github.com/ndunl075/badge/sidecar/wba"
	"gopkg.in/yaml.v3"
)

// Config is the proxy's whole configuration.
type Config struct {
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`

	// Authority is "host", "forwarded", or "fixed:example.com".
	//
	// Defaults to host. Trusting forwarding headers is opt-in because they are
	// attacker-controlled unless something the operator runs strips them from
	// client requests.
	Authority string `yaml:"authority"`
	Scheme    string `yaml:"scheme"`

	// DryRun evaluates the policy fully, records what it would have done, and
	// acts log-only regardless. This is how an operator earns the confidence to
	// enforce.
	DryRun       bool   `yaml:"dryRun"`
	DenyStatus   int    `yaml:"denyStatus"`
	DenyBody     string `yaml:"denyBody"`
	DebugHeaders bool   `yaml:"debugHeaders"`

	PolicyFile string         `yaml:"policyFile"`
	Policy     *policy.Policy `yaml:"policy"`

	AllowedOrigins     []string `yaml:"allowedOrigins"`
	ClockSkewSec       int64    `yaml:"clockSkewSec"`
	MaxAgeSec          int64    `yaml:"maxAgeSec"`
	DirectoryTimeoutMs int64    `yaml:"directoryTimeoutMs"`
	// AllowPrivateDirectories removes the guard that stops an attacker-supplied
	// Signature-Agent pointing the proxy at an internal address. Only for a
	// directory hosted inside a trusted network.
	AllowPrivateDirectories bool `yaml:"allowPrivateDirectories"`
}

// LoadConfig reads and validates a YAML or JSON configuration file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	decoder.KnownFields(true)

	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.Upstream == "" {
		return nil, fmt.Errorf("%s: upstream is required", path)
	}
	if cfg.Policy != nil && cfg.PolicyFile != "" {
		return nil, fmt.Errorf("%s: set policy or policyFile, not both", path)
	}
	return &cfg, nil
}

// Build assembles a handler from configuration.
func (c *Config) Build(sink Sink) (*Handler, error) {
	loaded := policy.DefaultPolicy
	switch {
	case c.PolicyFile != "":
		raw, err := os.ReadFile(c.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", c.PolicyFile, err)
		}
		parsed, err := policy.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.PolicyFile, err)
		}
		loaded = *parsed
	case c.Policy != nil:
		loaded = *c.Policy
	}

	engine, err := policy.Compile(loaded)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(c.DirectoryTimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = time.Second
	}
	resolver := directory.New(directory.Options{
		Fetcher: directory.NewHTTPFetcher(directory.ClientOptions{
			AllowPrivateAddresses: c.AllowPrivateDirectories,
		}),
		Timeout:        timeout,
		AllowedOrigins: c.AllowedOrigins,
	})

	verifier := wba.NewVerifier(resolver)
	if c.ClockSkewSec != 0 {
		verifier.ClockSkewSec = c.ClockSkewSec
	}
	if c.MaxAgeSec != 0 {
		verifier.MaxAgeSec = c.MaxAgeSec
	}
	verifier.AllowedOrigins = c.AllowedOrigins

	upstream, err := NewUpstream(c.Upstream)
	if err != nil {
		return nil, err
	}

	authority, err := parseAuthority(c.Authority)
	if err != nil {
		return nil, err
	}
	scheme, err := parseScheme(c.Scheme)
	if err != nil {
		return nil, err
	}

	return &Handler{
		Verifier: verifier, Policy: engine, Upstream: upstream, Sink: sink,
		Authority: authority, Scheme: scheme,
		DryRun: c.DryRun, DenyStatus: c.DenyStatus, DenyBody: c.DenyBody,
		DebugHeaders: c.DebugHeaders,
	}, nil
}

func parseAuthority(value string) (AuthoritySource, error) {
	switch {
	case value == "" || value == "host":
		return AuthoritySource{Mode: "host"}, nil
	case value == "forwarded":
		return AuthoritySource{Mode: "forwarded"}, nil
	}
	if fixed, ok := strings.CutPrefix(value, "fixed:"); ok && fixed != "" {
		return AuthoritySource{Mode: "fixed", Fixed: fixed}, nil
	}
	return AuthoritySource{}, fmt.Errorf(`authority must be "host", "forwarded" or "fixed:<host>", got %q`, value)
}

func parseScheme(value string) (SchemeSource, error) {
	switch value {
	case "", "auto":
		return SchemeSource{Mode: "auto"}, nil
	case "http", "https", "forwarded":
		return SchemeSource{Mode: value}, nil
	}
	return SchemeSource{}, fmt.Errorf(`scheme must be auto, http, https or forwarded, got %q`, value)
}

// Healthz answers readiness checks without going through the doorman.
func Healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("content-type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
