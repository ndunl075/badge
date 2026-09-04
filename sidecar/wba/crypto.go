package wba

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// JWK is a key as published in a directory, plus the validity window the Web
// Bot Auth directory draft adds.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	K   string `json:"k,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Nbf *int64 `json:"nbf,omitempty"`
	Exp *int64 `json:"exp,omitempty"`
}

// ErrKey reports a key that cannot be used.
var ErrKey = errors.New("unusable key")

// CanonicalJSON returns the RFC 7638 canonical form: required members only, in
// lexicographic order, no whitespace.
//
// Exported because it is the part worth pinning. A thumbprint that disagrees
// with other implementations by one byte of JSON is a key_not_found verdict
// nobody can debug from the outside.
func CanonicalJSON(key JWK) (string, error) {
	quote := func(s string) string {
		encoded, _ := json.Marshal(s)
		return string(encoded)
	}
	need := func(value, member string) error {
		if value == "" {
			return fmt.Errorf("%w: missing required member %q", ErrKey, member)
		}
		return nil
	}

	switch key.Kty {
	case "OKP":
		if err := need(key.Crv, "crv"); err != nil {
			return "", err
		}
		if err := need(key.X, "x"); err != nil {
			return "", err
		}
		return fmt.Sprintf(`{"crv":%s,"kty":"OKP","x":%s}`, quote(key.Crv), quote(key.X)), nil
	case "EC":
		if err := need(key.Crv, "crv"); err != nil {
			return "", err
		}
		if err := need(key.X, "x"); err != nil {
			return "", err
		}
		if err := need(key.Y, "y"); err != nil {
			return "", err
		}
		return fmt.Sprintf(`{"crv":%s,"kty":"EC","x":%s,"y":%s}`, quote(key.Crv), quote(key.X), quote(key.Y)), nil
	case "RSA":
		if err := need(key.E, "e"); err != nil {
			return "", err
		}
		if err := need(key.N, "n"); err != nil {
			return "", err
		}
		return fmt.Sprintf(`{"e":%s,"kty":"RSA","n":%s}`, quote(key.E), quote(key.N)), nil
	case "oct":
		if err := need(key.K, "k"); err != nil {
			return "", err
		}
		return fmt.Sprintf(`{"k":%s,"kty":"oct"}`, quote(key.K)), nil
	}
	return "", fmt.Errorf("%w: unsupported key type %q", ErrKey, key.Kty)
}

// Thumbprint computes the RFC 7638 JWK thumbprint, base64url without padding.
//
// This is the keyid a Web Bot Auth signer presents. It is always computed
// locally rather than read from the directory's own kid member: trusting that
// label would let one key in a directory impersonate another in the same
// directory.
func Thumbprint(key JWK) (string, error) {
	canonical, err := CanonicalJSON(key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func IsEd25519(key JWK) bool {
	return key.Kty == "OKP" && key.Crv == "Ed25519"
}

// PublicKey decodes an Ed25519 public key from its JWK.
func PublicKey(key JWK) (ed25519.PublicKey, error) {
	if !IsEd25519(key) {
		return nil, fmt.Errorf("%w: not an Ed25519 key", ErrKey)
	}
	raw, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("%w: x is not base64url", ErrKey)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: x is %d bytes, want %d", ErrKey, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Validity reports whether a directory key's nbf/exp window contains now, with
// nbf inclusive and exp exclusive.
type Validity string

const (
	ValidityValid       Validity = "valid"
	ValidityNotYetValid Validity = "not-yet-valid"
	ValidityExpired     Validity = "expired"
)

func KeyValidityAt(key JWK, now int64) Validity {
	if key.Nbf != nil && now < *key.Nbf {
		return ValidityNotYetValid
	}
	if key.Exp != nil && now >= *key.Exp {
		return ValidityExpired
	}
	return ValidityValid
}

// PublicOnly reduces any JWK to the members a directory should publish.
//
// A whitelist rather than a blacklist: deleting the private member from an
// exported key leaves key_ops and ext behind, which is a public key advertising
// that it can sign. Enumerating what may be published cannot fail that way.
func PublicOnly(key JWK) JWK {
	return JWK{
		Kty: key.Kty, Crv: key.Crv, X: key.X, Y: key.Y, N: key.N, E: key.E,
		Kid: key.Kid, Alg: key.Alg, Use: key.Use, Nbf: key.Nbf, Exp: key.Exp,
	}
}
