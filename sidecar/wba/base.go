package wba

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/ndunl075/badge/sidecar/sfv"
)

// BaseError carries the reason code a failed base construction should report.
//
// The distinction it preserves is the important one: a component the caller
// signed but did not send is their mistake, while a legitimate RFC 9421 feature
// this implementation lacks is ours. Guessing at a base we cannot build would
// surface as signature_invalid and libel a well-behaved caller.
type BaseError struct {
	Message string
	Reason  Reason
}

func (e *BaseError) Error() string { return e.Message }

func baseErr(reason Reason, format string, args ...any) *BaseError {
	return &BaseError{Message: fmt.Sprintf(format, args...), Reason: reason}
}

// StructuredFieldType says how a field is typed, so ;sf and ;key can
// canonicalize it.
type StructuredFieldType string

const (
	FieldDictionary StructuredFieldType = "dictionary"
	FieldList       StructuredFieldType = "list"
	FieldItem       StructuredFieldType = "item"
)

// DefaultStructuredFields is deliberately short. Canonicalizing a field under
// the wrong type produces a different base and so a signature_invalid verdict —
// a well-behaved caller reported as hostile. An unlisted field reports
// unsupported_component instead, which is honest.
var DefaultStructuredFields = map[string]StructuredFieldType{
	"accept":          FieldList,
	"accept-encoding": FieldList,
	"accept-language": FieldList,
	"cache-control":   FieldDictionary,
	"content-digest":  FieldDictionary,
	"content-length":  FieldItem,
	"content-type":    FieldItem,
	"signature":       FieldDictionary,
	"signature-input": FieldDictionary,
}

// unimplementedParams apply only to response signatures, which this
// implementation does not verify.
var unimplementedParams = map[string]bool{"req": true, "tr": true}

// BuildBase constructs the RFC 9421 section 2.5 signature base: one line per
// covered component terminated by LF, then the @signature-params line with no
// trailing LF.
//
// signatureParamsSource must be the received bytes of the Signature-Input
// dictionary member, not a re-serialization of it.
func BuildBase(
	req *Request,
	components []sfv.Item,
	signatureParamsSource string,
	extraTypes map[string]StructuredFieldType,
) (string, error) {
	types := DefaultStructuredFields
	if len(extraTypes) > 0 {
		types = make(map[string]StructuredFieldType, len(DefaultStructuredFields)+len(extraTypes))
		for k, v := range DefaultStructuredFields {
			types[k] = v
		}
		for k, v := range extraTypes {
			types[k] = v
		}
	}

	lines := make([]string, 0, len(components)+1)
	seen := map[string]bool{}

	for _, component := range components {
		if component.Value.Kind != sfv.KindString {
			return "", baseErr(ReasonSignatureInputMalformed, "component identifiers must be strings")
		}
		name := component.Value.Str
		if name != strings.ToLower(name) {
			return "", baseErr(ReasonSignatureInputMalformed, "component identifier must be lowercase: %s", name)
		}
		for _, param := range component.Params.Keys() {
			if unimplementedParams[param] {
				return "", baseErr(ReasonUnsupportedComponent, "component parameter ;%s is not implemented", param)
			}
		}

		identifier, err := sfv.SerializeItem(component)
		if err != nil {
			return "", baseErr(ReasonSignatureInputMalformed, "unserializable component identifier")
		}
		if seen[identifier] {
			return "", baseErr(ReasonSignatureInputMalformed, "duplicate covered component: %s", identifier)
		}
		seen[identifier] = true

		value, err := componentValue(name, component, req, types)
		if err != nil {
			return "", err
		}
		lines = append(lines, identifier+": "+value)
	}

	lines = append(lines, `"@signature-params": `+signatureParamsSource)
	return strings.Join(lines, "\n"), nil
}

func componentValue(
	name string,
	component sfv.Item,
	req *Request,
	types map[string]StructuredFieldType,
) (string, error) {
	if !strings.HasPrefix(name, "@") {
		return fieldComponent(name, component, req, types)
	}
	switch name {
	case "@method":
		// RFC 9421 section 2.2.1 takes the method as-is and notes that method
		// names are case-sensitive. Uppercasing would disagree with a correct
		// signer on a non-standard method.
		return req.Method, nil
	case "@authority":
		return normalizeAuthority(req.Authority, req.Scheme), nil
	case "@scheme":
		return req.Scheme, nil
	case "@path":
		if req.Path == "" {
			return "/", nil
		}
		return req.Path, nil
	case "@query":
		return "?" + req.Query, nil
	case "@request-target":
		if req.Query == "" {
			return req.Path, nil
		}
		return req.Path + "?" + req.Query, nil
	case "@target-uri":
		return targetURI(req), nil
	case "@query-param":
		return queryParam(component, req)
	case "@status":
		return "", baseErr(ReasonUnsupportedComponent, "@status is only valid for response signatures")
	}
	return "", baseErr(ReasonUnsupportedComponent, "unknown derived component: %s", name)
}

func flagSet(component sfv.Item, name string) (bool, error) {
	value, ok := component.Params.Get(name)
	if !ok {
		return false, nil
	}
	if value.Kind != sfv.KindBoolean {
		return false, baseErr(ReasonSignatureInputMalformed, ";%s must be a boolean", name)
	}
	// RFC 9651 lets a signer write ;sf=?0, which means the flag is off.
	return value.Bool, nil
}

func fieldComponent(
	name string,
	component sfv.Item,
	req *Request,
	types map[string]StructuredFieldType,
) (string, error) {
	bs, err := flagSet(component, "bs")
	if err != nil {
		return "", err
	}
	sf, err := flagSet(component, "sf")
	if err != nil {
		return "", err
	}
	keyParam, hasKey := component.Params.Get("key")
	if hasKey && keyParam.Kind != sfv.KindString {
		return "", baseErr(ReasonSignatureInputMalformed, ";key must be a string")
	}
	if bs && (sf || hasKey) {
		return "", baseErr(ReasonSignatureInputMalformed, ";bs cannot be combined with ;sf or ;key")
	}

	if bs {
		return byteSequenceValue(name, req)
	}
	if sf || hasKey {
		key := ""
		if hasKey {
			key = keyParam.Str
		}
		return structuredValue(name, req, types, key, hasKey)
	}
	return fieldValue(name, req)
}

func fieldValue(name string, req *Request) (string, error) {
	value, ok := req.Header(name)
	if !ok {
		return "", baseErr(ReasonCoveredComponentMissing, "covered field is not present in the request: %s", name)
	}
	return normalizeFieldValue(value), nil
}

// normalizeFieldValue strips surrounding OWS and collapses obs-folds, per
// RFC 9421 section 2.1.
func normalizeFieldValue(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\r' && i+1 < len(value) && value[i+1] == '\n' {
			i++
			continue
		}
		if c == '\n' {
			continue
		}
		out.WriteByte(c)
	}
	folded := out.String()
	for strings.Contains(folded, "\t") {
		folded = strings.ReplaceAll(folded, "\t", " ")
	}
	return strings.TrimSpace(folded)
}

// byteSequenceValue implements ;bs: each field value becomes its own byte
// sequence, combined as a List.
func byteSequenceValue(name string, req *Request) (string, error) {
	values, ok := req.HeaderValues(name)
	if !ok {
		return "", baseErr(ReasonCoveredComponentMissing, "covered field is not present in the request: %s", name)
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeFieldValue(value)
		parts = append(parts, ":"+base64.StdEncoding.EncodeToString([]byte(normalized))+":")
	}
	return strings.Join(parts, ", "), nil
}

func structuredValue(
	name string,
	req *Request,
	types map[string]StructuredFieldType,
	key string,
	hasKey bool,
) (string, error) {
	raw, err := fieldValue(name, req)
	if err != nil {
		return "", err
	}

	// ;key only has meaning for a Dictionary, so it settles the type by itself.
	fieldType := FieldDictionary
	if !hasKey {
		known, ok := types[name]
		if !ok {
			return "", baseErr(ReasonUnsupportedComponent,
				"no structured field type is known for %q, so ;sf cannot canonicalize it", name)
		}
		fieldType = known
	}

	switch fieldType {
	case FieldDictionary:
		dict, err := sfv.ParseDictionary(raw)
		if err != nil {
			return "", baseErr(ReasonCoveredFieldNotStructured, "covered field %s is not a valid dictionary", name)
		}
		if !hasKey {
			out, err := sfv.SerializeDictionary(dict)
			if err != nil {
				return "", baseErr(ReasonCoveredFieldNotStructured, "covered field %s cannot be re-serialized", name)
			}
			return out, nil
		}
		entry, ok := dict.Get(key)
		if !ok {
			return "", baseErr(ReasonCoveredComponentMissing, "covered dictionary key is not present in %s: %s", name, key)
		}
		out, err := sfv.SerializeMember(entry.Member)
		if err != nil {
			return "", baseErr(ReasonCoveredFieldNotStructured, "covered member cannot be re-serialized")
		}
		return out, nil
	case FieldList:
		list, err := sfv.ParseList(raw)
		if err != nil {
			return "", baseErr(ReasonCoveredFieldNotStructured, "covered field %s is not a valid list", name)
		}
		out, err := sfv.SerializeList(list)
		if err != nil {
			return "", baseErr(ReasonCoveredFieldNotStructured, "covered field %s cannot be re-serialized", name)
		}
		return out, nil
	default:
		item, err := sfv.ParseItem(raw)
		if err != nil {
			return "", baseErr(ReasonCoveredFieldNotStructured, "covered field %s is not a valid item", name)
		}
		out, err := sfv.SerializeItem(item)
		if err != nil {
			return "", baseErr(ReasonCoveredFieldNotStructured, "covered field %s cannot be re-serialized", name)
		}
		return out, nil
	}
}

// normalizeAuthority lowercases and drops the default port for the scheme, per
// RFC 9421 section 2.2.3.
func normalizeAuthority(authority, scheme string) string {
	lower := strings.ToLower(authority)
	defaultPort := ":80"
	if scheme == "https" {
		defaultPort = ":443"
	}
	return strings.TrimSuffix(lower, defaultPort)
}

func targetURI(req *Request) string {
	authority := normalizeAuthority(req.Authority, req.Scheme)
	path := req.Path
	if path == "" {
		path = "/"
	}
	uri := req.Scheme + "://" + authority + path
	if req.Query != "" {
		uri += "?" + req.Query
	}
	return uri
}

func queryParam(component sfv.Item, req *Request) (string, error) {
	target, ok := component.Params.GetString("name")
	if !ok {
		return "", baseErr(ReasonSignatureInputMalformed, `@query-param requires a ;name="..." parameter`)
	}
	var matches []string
	for _, pair := range strings.Split(req.Query, "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		if name == target {
			matches = append(matches, value)
		}
	}
	if len(matches) == 0 {
		return "", baseErr(ReasonCoveredComponentMissing, "covered query parameter is not present: %s", target)
	}
	// RFC 9421 section 2.2.8 leaves repeated parameters ambiguous enough that
	// two implementations can disagree. Refusing is the only option that cannot
	// silently verify a base the signer did not produce.
	if len(matches) > 1 {
		return "", baseErr(ReasonUnsupportedComponent, "query parameter appears more than once: %s", target)
	}
	decoded, err := url.QueryUnescape(matches[0])
	if err != nil {
		// Caller-controlled input, so this must not surface as internal_error,
		// which is reserved for our own failures.
		return "", baseErr(ReasonCoveredComponentMalformed, "covered query parameter is not valid percent-encoding: %s", target)
	}
	return decoded, nil
}
