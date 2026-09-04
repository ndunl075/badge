package sfv

import (
	"encoding/base64"
	"strconv"
	"strings"
	"unicode/utf8"
)

type parser struct {
	s string
	i int
}

func (p *parser) fail(msg string) error {
	return &ParseError{Message: msg, Position: p.i}
}

func (p *parser) eof() bool { return p.i >= len(p.s) }

func (p *parser) peek() (byte, bool) {
	if p.eof() {
		return 0, false
	}
	return p.s[p.i], true
}

func (p *parser) skipSP() {
	for p.i < len(p.s) && p.s[p.i] == ' ' {
		p.i++
	}
}

func (p *parser) skipOWS() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *parser) expect(c byte) error {
	if b, ok := p.peek(); !ok || b != c {
		return p.fail("expected " + strconv.QuoteRune(rune(c)))
	}
	p.i++
	return nil
}

// ParseDictionary parses a Dictionary field value (RFC 9651 section 3.2), such
// as Signature-Input.
func ParseDictionary(input string) (*Dictionary, error) {
	p := &parser{s: input}
	dict := &Dictionary{}
	p.skipSP()
	for !p.eof() {
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		var entry DictEntry
		if b, ok := p.peek(); ok && b == '=' {
			p.i++
			start := p.i
			member, err := p.parseItemOrInnerList()
			if err != nil {
				return nil, err
			}
			entry = DictEntry{Member: member, Source: p.s[start:p.i]}
		} else {
			start := p.i
			params, err := p.parseParams()
			if err != nil {
				return nil, err
			}
			entry = DictEntry{
				Member: Member{Item: Item{Value: Boolean(true), Params: params}},
				Source: p.s[start:p.i],
			}
		}
		dict.set(key, entry)
		p.skipOWS()
		if p.eof() {
			return dict, nil
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		p.skipOWS()
		if p.eof() {
			return nil, p.fail("trailing comma in dictionary")
		}
	}
	return dict, nil
}

// ParseList parses a List field value (RFC 9651 section 3.1).
func ParseList(input string) ([]Member, error) {
	p := &parser{s: input}
	var members []Member
	p.skipSP()
	for !p.eof() {
		member, err := p.parseItemOrInnerList()
		if err != nil {
			return nil, err
		}
		members = append(members, member)
		p.skipOWS()
		if p.eof() {
			return members, nil
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
		p.skipOWS()
		if p.eof() {
			return nil, p.fail("trailing comma in list")
		}
	}
	return members, nil
}

// ParseItem parses an Item field value (RFC 9651 section 3.3), such as
// Signature-Agent.
func ParseItem(input string) (Item, error) {
	p := &parser{s: input}
	p.skipSP()
	value, err := p.parseBareItem()
	if err != nil {
		return Item{}, err
	}
	params, err := p.parseParams()
	if err != nil {
		return Item{}, err
	}
	p.skipSP()
	if !p.eof() {
		return Item{}, p.fail("unexpected trailing characters")
	}
	return Item{Value: value, Params: params}, nil
}

func (p *parser) parseItemOrInnerList() (Member, error) {
	if b, ok := p.peek(); ok && b == '(' {
		list, err := p.parseInnerList()
		if err != nil {
			return Member{}, err
		}
		return Member{IsInnerList: true, InnerList: list}, nil
	}
	item, err := p.parseItemWithParams()
	if err != nil {
		return Member{}, err
	}
	return Member{Item: item}, nil
}

func (p *parser) parseItemWithParams() (Item, error) {
	value, err := p.parseBareItem()
	if err != nil {
		return Item{}, err
	}
	params, err := p.parseParams()
	if err != nil {
		return Item{}, err
	}
	return Item{Value: value, Params: params}, nil
}

func (p *parser) parseInnerList() (InnerList, error) {
	if err := p.expect('('); err != nil {
		return InnerList{}, err
	}
	items := []Item{}
	for {
		p.skipSP()
		if b, ok := p.peek(); ok && b == ')' {
			p.i++
			params, err := p.parseParams()
			if err != nil {
				return InnerList{}, err
			}
			return InnerList{Items: items, Params: params}, nil
		}
		item, err := p.parseItemWithParams()
		if err != nil {
			return InnerList{}, err
		}
		items = append(items, item)
		b, ok := p.peek()
		if !ok || (b != ' ' && b != ')') {
			return InnerList{}, p.fail(`expected SP or ")" in inner list`)
		}
	}
}

func (p *parser) parseParams() (*Params, error) {
	params := NewParams()
	for {
		b, ok := p.peek()
		if !ok || b != ';' {
			return params, nil
		}
		p.i++
		p.skipSP()
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		value := Boolean(true)
		if b, ok := p.peek(); ok && b == '=' {
			p.i++
			value, err = p.parseBareItem()
			if err != nil {
				return nil, err
			}
		}
		params.Set(key, value)
	}
}

func (p *parser) parseKey() (string, error) {
	b, ok := p.peek()
	if !ok || !(isLCAlpha(b) || b == '*') {
		return "", p.fail("expected a key")
	}
	start := p.i
	p.i++
	for !p.eof() {
		c := p.s[p.i]
		if isLCAlpha(c) || isDigit(c) || c == '_' || c == '-' || c == '.' || c == '*' {
			p.i++
			continue
		}
		break
	}
	return p.s[start:p.i], nil
}

func (p *parser) parseBareItem() (BareItem, error) {
	b, ok := p.peek()
	if !ok {
		return BareItem{}, p.fail("expected a bare item")
	}
	switch {
	case b == '-' || isDigit(b):
		return p.parseNumber()
	case b == '"':
		s, err := p.parseString()
		return String(s), err
	case b == ':':
		v, err := p.parseByteSequence()
		return Binary(v), err
	case b == '?':
		v, err := p.parseBoolean()
		return Boolean(v), err
	case b == '@':
		v, err := p.parseDate()
		return Date(v), err
	case b == '%':
		v, err := p.parseDisplayString()
		return BareItem{Kind: KindDisplayString, Str: v}, err
	case b == '*' || isAlpha(b):
		v, err := p.parseToken()
		return Token(v), err
	}
	return BareItem{}, p.fail("unrecognized bare item")
}

func (p *parser) parseNumber() (BareItem, error) {
	sign := int64(1)
	if b, ok := p.peek(); ok && b == '-' {
		p.i++
		sign = -1
	}
	b, ok := p.peek()
	if !ok || !isDigit(b) {
		return BareItem{}, p.fail("expected a digit")
	}
	var digits strings.Builder
	isDecimal := false
	for !p.eof() {
		c := p.s[p.i]
		switch {
		case isDigit(c):
			digits.WriteByte(c)
			p.i++
		case !isDecimal && c == '.':
			if digits.Len() > 12 {
				return BareItem{}, p.fail("too many digits before the decimal point")
			}
			digits.WriteByte(c)
			isDecimal = true
			p.i++
		default:
			goto done
		}
		if !isDecimal && digits.Len() > 15 {
			return BareItem{}, p.fail("integer too long")
		}
		if isDecimal && digits.Len() > 16 {
			return BareItem{}, p.fail("decimal too long")
		}
	}
done:
	text := digits.String()
	if !isDecimal {
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return BareItem{}, p.fail("invalid integer")
		}
		return Integer(sign * n), nil
	}
	dot := strings.IndexByte(text, '.')
	if dot == len(text)-1 {
		return BareItem{}, p.fail("decimal must have digits after the point")
	}
	if len(text)-dot-1 > 3 {
		return BareItem{}, p.fail("at most three fractional digits")
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return BareItem{}, p.fail("invalid decimal")
	}
	return Decimal(float64(sign) * f), nil
}

func (p *parser) parseString() (string, error) {
	if err := p.expect('"'); err != nil {
		return "", err
	}
	var out strings.Builder
	for !p.eof() {
		c := p.s[p.i]
		p.i++
		switch {
		case c == '\\':
			if p.eof() {
				return "", p.fail("unterminated string escape")
			}
			next := p.s[p.i]
			p.i++
			if next != '"' && next != '\\' {
				return "", p.fail("invalid string escape")
			}
			out.WriteByte(next)
		case c == '"':
			return out.String(), nil
		case c < 0x20 || c > 0x7e:
			return "", p.fail("invalid character in string")
		default:
			out.WriteByte(c)
		}
	}
	return "", p.fail("unterminated string")
}

func (p *parser) parseToken() (string, error) {
	b, ok := p.peek()
	if !ok || !(isAlpha(b) || b == '*') {
		return "", p.fail("expected a token")
	}
	start := p.i
	p.i++
	for !p.eof() {
		c := p.s[p.i]
		if isTchar(c) || c == ':' || c == '/' {
			p.i++
			continue
		}
		break
	}
	return p.s[start:p.i], nil
}

func (p *parser) parseByteSequence() ([]byte, error) {
	if err := p.expect(':'); err != nil {
		return nil, err
	}
	end := strings.IndexByte(p.s[p.i:], ':')
	if end == -1 {
		return nil, p.fail("unterminated byte sequence")
	}
	encoded := p.s[p.i : p.i+end]
	p.i += end + 1
	for i := 0; i < len(encoded); i++ {
		c := encoded[i]
		if !(isAlpha(c) || isDigit(c) || c == '+' || c == '/' || c == '=') {
			return nil, p.fail("invalid base64 in byte sequence")
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, p.fail("invalid base64 in byte sequence")
	}
	return decoded, nil
}

func (p *parser) parseBoolean() (bool, error) {
	if err := p.expect('?'); err != nil {
		return false, err
	}
	b, ok := p.peek()
	if !ok {
		return false, p.fail("expected ?0 or ?1")
	}
	p.i++
	switch b {
	case '1':
		return true, nil
	case '0':
		return false, nil
	}
	return false, p.fail("expected ?0 or ?1")
}

func (p *parser) parseDate() (int64, error) {
	if err := p.expect('@'); err != nil {
		return 0, err
	}
	n, err := p.parseNumber()
	if err != nil {
		return 0, err
	}
	if n.Kind != KindInteger {
		return 0, p.fail("date must be an integer")
	}
	return n.Int, nil
}

func (p *parser) parseDisplayString() (string, error) {
	if err := p.expect('%'); err != nil {
		return "", err
	}
	if err := p.expect('"'); err != nil {
		return "", err
	}
	var bytes []byte
	for !p.eof() {
		c := p.s[p.i]
		p.i++
		switch {
		case c == '%':
			if p.i+2 > len(p.s) {
				return "", p.fail("invalid percent escape in display string")
			}
			hex := p.s[p.i : p.i+2]
			if !isLowerHex(hex[0]) || !isLowerHex(hex[1]) {
				return "", p.fail("invalid percent escape in display string")
			}
			n, err := strconv.ParseUint(hex, 16, 8)
			if err != nil {
				return "", p.fail("invalid percent escape in display string")
			}
			p.i += 2
			bytes = append(bytes, byte(n))
		case c == '"':
			if !utf8.Valid(bytes) {
				return "", p.fail("display string is not valid UTF-8")
			}
			return string(bytes), nil
		case c == '\\' || c < 0x20 || c > 0x7e:
			return "", p.fail("invalid character in display string")
		default:
			bytes = append(bytes, c)
		}
	}
	return "", p.fail("unterminated display string")
}

func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isLCAlpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isAlpha(c byte) bool   { return isLCAlpha(c) || (c >= 'A' && c <= 'Z') }
func isLowerHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f')
}
func isTchar(c byte) bool {
	if isAlpha(c) || isDigit(c) {
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}
