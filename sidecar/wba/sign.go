package wba

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/ndunl075/badge/sidecar/sfv"
)

// SignOptions describes one Web Bot Auth signature.
type SignOptions struct {
	PrivateKey ed25519.PrivateKey
	Keyid      string
	// Components are covered component identifiers as they appear in
	// Signature-Input, e.g. `"@authority"`.
	Components     []string
	Created        int64
	Expires        int64
	Label          string
	SignatureAgent string
	Nonce          string
	Tag            string
	Alg            string
}

// SignedFields are the headers a signer adds.
type SignedFields struct {
	SignatureInput string
	Signature      string
	// Base is the exact signature base that was signed — the thing to diff when
	// a verification fails.
	Base string
}

// Sign produces the Signature-Input and Signature headers for a request.
//
// Exported because a Go agent needs it, and because the proxy's own tests
// should verify real signatures rather than fixtures they also produced by
// hand.
func Sign(req *Request, opts SignOptions) (SignedFields, error) {
	label := opts.Label
	if label == "" {
		label = "sig1"
	}
	tag := opts.Tag
	if tag == "" {
		tag = DefaultProfile.Tag
	}
	alg := opts.Alg
	if alg == "" {
		alg = "ed25519"
	}
	components := opts.Components
	if components == nil {
		components = []string{`"@authority"`}
		if opts.SignatureAgent != "" {
			components = append(components, `"signature-agent"`)
		}
	}

	items := make([]sfv.Item, 0, len(components))
	for _, id := range components {
		item, err := sfv.ParseItem(id)
		if err != nil {
			return SignedFields{}, fmt.Errorf("component %q: %w", id, err)
		}
		items = append(items, item)
	}

	params := sfv.NewParams()
	params.Set("created", sfv.Integer(opts.Created))
	params.Set("expires", sfv.Integer(opts.Expires))
	params.Set("keyid", sfv.String(opts.Keyid))
	params.Set("alg", sfv.String(alg))
	params.Set("tag", sfv.String(tag))
	if opts.Nonce != "" {
		params.Set("nonce", sfv.String(opts.Nonce))
	}

	source, err := sfv.SerializeInnerList(sfv.InnerList{Items: items, Params: params})
	if err != nil {
		return SignedFields{}, err
	}

	base, err := BuildBase(req, items, source, nil)
	if err != nil {
		return SignedFields{}, err
	}
	signature := ed25519.Sign(opts.PrivateKey, []byte(base))

	return SignedFields{
		SignatureInput: label + "=" + source,
		Signature:      label + "=:" + base64.StdEncoding.EncodeToString(signature) + ":",
		Base:           base,
	}, nil
}
