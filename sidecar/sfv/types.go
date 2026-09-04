// Package sfv implements RFC 9651 Structured Field Values.
//
// This is a second implementation of packages/core/src/sfv, written from the
// RFC rather than translated line by line, so that a disagreement between the
// two is evidence about the spec rather than a shared typo carried across.
package sfv

import "fmt"

// Kind distinguishes bare item types. The distinction that matters most is
// String vs Token: tag="web-bot-auth" is a String, and a Token spelling the
// same thing must not compare equal.
type Kind uint8

const (
	KindInteger Kind = iota
	KindDecimal
	KindString
	KindToken
	KindBinary
	KindBoolean
	KindDate
	KindDisplayString
)

func (k Kind) String() string {
	switch k {
	case KindInteger:
		return "integer"
	case KindDecimal:
		return "decimal"
	case KindString:
		return "string"
	case KindToken:
		return "token"
	case KindBinary:
		return "binary"
	case KindBoolean:
		return "boolean"
	case KindDate:
		return "date"
	case KindDisplayString:
		return "displaystring"
	}
	return "unknown"
}

// BareItem is a single structured field value.
type BareItem struct {
	Kind Kind
	Int  int64   // integer, date
	Dec  float64 // decimal
	Str  string  // string, token, display string
	Bin  []byte  // byte sequence
	Bool bool
}

func Integer(v int64) BareItem   { return BareItem{Kind: KindInteger, Int: v} }
func Decimal(v float64) BareItem { return BareItem{Kind: KindDecimal, Dec: v} }
func String(v string) BareItem   { return BareItem{Kind: KindString, Str: v} }
func Token(v string) BareItem    { return BareItem{Kind: KindToken, Str: v} }
func Binary(v []byte) BareItem   { return BareItem{Kind: KindBinary, Bin: v} }
func Boolean(v bool) BareItem    { return BareItem{Kind: KindBoolean, Bool: v} }
func Date(v int64) BareItem      { return BareItem{Kind: KindDate, Int: v} }

// Params is an ordered parameter map. Order is preserved because it is
// signature-relevant.
type Params struct {
	keys []string
	vals map[string]BareItem
}

func NewParams() *Params { return &Params{vals: map[string]BareItem{}} }

func (p *Params) Set(key string, value BareItem) {
	if p.vals == nil {
		p.vals = map[string]BareItem{}
	}
	if _, seen := p.vals[key]; seen {
		// A repeated parameter replaces the earlier one and takes its new
		// position, per RFC 9651 section 4.2.3.2.
		p.keys = removeString(p.keys, key)
	}
	p.keys = append(p.keys, key)
	p.vals[key] = value
}

func (p *Params) Get(key string) (BareItem, bool) {
	if p == nil || p.vals == nil {
		return BareItem{}, false
	}
	v, ok := p.vals[key]
	return v, ok
}

func (p *Params) Has(key string) bool {
	_, ok := p.Get(key)
	return ok
}

// GetString returns the value of a String parameter. A Token of the same
// spelling is deliberately not accepted.
func (p *Params) GetString(key string) (string, bool) {
	v, ok := p.Get(key)
	if !ok || v.Kind != KindString {
		return "", false
	}
	return v.Str, true
}

func (p *Params) GetInteger(key string) (int64, bool) {
	v, ok := p.Get(key)
	if !ok || v.Kind != KindInteger {
		return 0, false
	}
	return v.Int, true
}

func (p *Params) Keys() []string {
	if p == nil {
		return nil
	}
	return p.keys
}

func (p *Params) Len() int {
	if p == nil {
		return 0
	}
	return len(p.keys)
}

func removeString(list []string, want string) []string {
	out := list[:0]
	for _, v := range list {
		if v != want {
			out = append(out, v)
		}
	}
	return out
}

// Item is a bare item with its parameters.
type Item struct {
	Value  BareItem
	Params *Params
}

// InnerList is a parenthesised list of items, with its own parameters.
type InnerList struct {
	Items  []Item
	Params *Params
}

// Member is either an Item or an InnerList.
type Member struct {
	IsInnerList bool
	Item        Item
	InnerList   InnerList
}

// DictEntry pairs a member with the exact received bytes it was parsed from.
//
// The source span exists for RFC 9421 @signature-params: the signer computed
// its base from its own serialization, so re-serializing a parse tree risks
// differing by a byte of spacing or number formatting and failing every
// signature. Slicing the received bytes removes that whole class of mismatch.
type DictEntry struct {
	Member Member
	Source string
}

// Dictionary preserves member order.
type Dictionary struct {
	keys    []string
	entries map[string]DictEntry
}

func (d *Dictionary) set(key string, entry DictEntry) {
	if d.entries == nil {
		d.entries = map[string]DictEntry{}
	}
	if _, seen := d.entries[key]; seen {
		d.keys = removeString(d.keys, key)
	}
	d.keys = append(d.keys, key)
	d.entries[key] = entry
}

func (d *Dictionary) Get(key string) (DictEntry, bool) {
	if d == nil || d.entries == nil {
		return DictEntry{}, false
	}
	e, ok := d.entries[key]
	return e, ok
}

func (d *Dictionary) Keys() []string {
	if d == nil {
		return nil
	}
	return d.keys
}

func (d *Dictionary) Len() int {
	if d == nil {
		return 0
	}
	return len(d.keys)
}

// ParseError reports where parsing gave up.
type ParseError struct {
	Message  string
	Position int
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s (at offset %d)", e.Message, e.Position)
}
