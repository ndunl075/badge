package sfv

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrSerialize reports a value that cannot be represented as a structured field.
var ErrSerialize = errors.New("cannot serialize structured field value")

const (
	maxInteger = 999999999999999
	minInteger = -999999999999999
)

// SerializeBareItem implements RFC 9651 section 4.1.
//
// Serialization is only used on the signing side. Verification never
// round-trips a received field through here; see DictEntry.Source.
func SerializeBareItem(item BareItem) (string, error) {
	switch item.Kind {
	case KindInteger:
		if item.Int > maxInteger || item.Int < minInteger {
			return "", fmt.Errorf("%w: integer out of range", ErrSerialize)
		}
		return strconv.FormatInt(item.Int, 10), nil
	case KindDecimal:
		rounded := float64(int64(item.Dec*1000+copySign(0.5, item.Dec))) / 1000
		text := strconv.FormatFloat(rounded, 'f', -1, 64)
		if !strings.Contains(text, ".") {
			text += ".0"
		}
		return text, nil
	case KindString:
		var out strings.Builder
		out.WriteByte('"')
		for i := 0; i < len(item.Str); i++ {
			c := item.Str[i]
			if c < 0x20 || c > 0x7e {
				return "", fmt.Errorf("%w: string must be printable ASCII", ErrSerialize)
			}
			if c == '"' || c == '\\' {
				out.WriteByte('\\')
			}
			out.WriteByte(c)
		}
		out.WriteByte('"')
		return out.String(), nil
	case KindToken:
		if !validToken(item.Str) {
			return "", fmt.Errorf("%w: invalid token %q", ErrSerialize, item.Str)
		}
		return item.Str, nil
	case KindBinary:
		return ":" + base64.StdEncoding.EncodeToString(item.Bin) + ":", nil
	case KindBoolean:
		if item.Bool {
			return "?1", nil
		}
		return "?0", nil
	case KindDate:
		return "@" + strconv.FormatInt(item.Int, 10), nil
	case KindDisplayString:
		var out strings.Builder
		out.WriteString(`%"`)
		for _, b := range []byte(item.Str) {
			if b == 0x25 || b == 0x22 || b <= 0x1f || b >= 0x7f {
				out.WriteString(fmt.Sprintf("%%%02x", b))
			} else {
				out.WriteByte(b)
			}
		}
		out.WriteByte('"')
		return out.String(), nil
	}
	return "", fmt.Errorf("%w: unknown kind", ErrSerialize)
}

func copySign(magnitude, sign float64) float64 {
	if sign < 0 {
		return -magnitude
	}
	return magnitude
}

func validToken(s string) bool {
	if s == "" {
		return false
	}
	if !(isAlpha(s[0]) || s[0] == '*') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(isTchar(c) || c == ':' || c == '/') {
			return false
		}
	}
	return true
}

func SerializeParams(params *Params) (string, error) {
	var out strings.Builder
	for _, key := range params.Keys() {
		value, _ := params.Get(key)
		out.WriteByte(';')
		out.WriteString(key)
		if value.Kind == KindBoolean && value.Bool {
			continue
		}
		text, err := SerializeBareItem(value)
		if err != nil {
			return "", err
		}
		out.WriteByte('=')
		out.WriteString(text)
	}
	return out.String(), nil
}

func SerializeItem(item Item) (string, error) {
	value, err := SerializeBareItem(item.Value)
	if err != nil {
		return "", err
	}
	params, err := SerializeParams(item.Params)
	if err != nil {
		return "", err
	}
	return value + params, nil
}

func SerializeInnerList(list InnerList) (string, error) {
	parts := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		text, err := SerializeItem(item)
		if err != nil {
			return "", err
		}
		parts = append(parts, text)
	}
	params, err := SerializeParams(list.Params)
	if err != nil {
		return "", err
	}
	return "(" + strings.Join(parts, " ") + ")" + params, nil
}

func SerializeMember(member Member) (string, error) {
	if member.IsInnerList {
		return SerializeInnerList(member.InnerList)
	}
	return SerializeItem(member.Item)
}

func SerializeList(members []Member) (string, error) {
	parts := make([]string, 0, len(members))
	for _, member := range members {
		text, err := SerializeMember(member)
		if err != nil {
			return "", err
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, ", "), nil
}

// SerializeDictionary re-serializes a dictionary from its parsed members,
// eliding "=?1" for boolean-true members as RFC 9651 requires.
func SerializeDictionary(dict *Dictionary) (string, error) {
	parts := make([]string, 0, dict.Len())
	for _, key := range dict.Keys() {
		entry, _ := dict.Get(key)
		member := entry.Member
		if !member.IsInnerList && member.Item.Value.Kind == KindBoolean && member.Item.Value.Bool {
			params, err := SerializeParams(member.Item.Params)
			if err != nil {
				return "", err
			}
			parts = append(parts, key+params)
			continue
		}
		text, err := SerializeMember(member)
		if err != nil {
			return "", err
		}
		parts = append(parts, key+"="+text)
	}
	return strings.Join(parts, ", "), nil
}
