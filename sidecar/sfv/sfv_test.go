package sfv

import (
	"strings"
	"testing"
)

func TestParseItemKinds(t *testing.T) {
	cases := []struct {
		input string
		kind  Kind
	}{
		{"42", KindInteger},
		{"-42", KindInteger},
		{"4.5", KindDecimal},
		{`"hi"`, KindString},
		{"foo123/456", KindToken},
		{"?1", KindBoolean},
		{"@1659578233", KindDate},
		{":aGVsbG8=:", KindBinary},
		{`%"caf%c3%a9"`, KindDisplayString},
	}
	for _, tc := range cases {
		item, err := ParseItem(tc.input)
		if err != nil {
			t.Fatalf("ParseItem(%q): %v", tc.input, err)
		}
		if item.Value.Kind != tc.kind {
			t.Errorf("ParseItem(%q) kind = %v, want %v", tc.input, item.Value.Kind, tc.kind)
		}
	}
}

// The distinction Badge most depends on: tag="web-bot-auth" is a String, and a
// Token spelling the same thing must not be accepted as one.
func TestTokensAndStringsAreDistinct(t *testing.T) {
	str, err := ParseItem(`"web-bot-auth"`)
	if err != nil || str.Value.Kind != KindString {
		t.Fatalf("quoted value should parse as a String, got %v %v", str.Value.Kind, err)
	}
	tok, err := ParseItem("web-bot-auth")
	if err != nil || tok.Value.Kind != KindToken {
		t.Fatalf("bare value should parse as a Token, got %v %v", tok.Value.Kind, err)
	}
}

func TestParseItemRejects(t *testing.T) {
	cases := []string{
		`"abc`, `"a\nb"`, "42 43", "4.", "4.5678", "1234567890123456",
		`%"caf%C3%A9"`, ":aGVsbG8=", ":not base64!:", "", "@165957.5",
	}
	for _, input := range cases {
		if _, err := ParseItem(input); err == nil {
			t.Errorf("ParseItem(%q) should have failed", input)
		}
	}
}

func TestParseDictionarySignatureInput(t *testing.T) {
	const input = `sig1=("@authority" "signature-agent");created=1735689600;expires=1735689660` +
		`;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";tag="web-bot-auth"`

	dict, err := ParseDictionary(input)
	if err != nil {
		t.Fatalf("ParseDictionary: %v", err)
	}
	entry, ok := dict.Get("sig1")
	if !ok || !entry.Member.IsInnerList {
		t.Fatal("expected an inner list under sig1")
	}
	if got := len(entry.Member.InnerList.Items); got != 2 {
		t.Fatalf("covered components = %d, want 2", got)
	}
	tag, ok := entry.Member.InnerList.Params.GetString("tag")
	if !ok || tag != "web-bot-auth" {
		t.Errorf("tag = %q %v, want web-bot-auth", tag, ok)
	}
	created, ok := entry.Member.InnerList.Params.GetInteger("created")
	if !ok || created != 1735689600 {
		t.Errorf("created = %d %v", created, ok)
	}

	// The reason DictEntry carries Source: the signer's own bytes are what it
	// signed over, so they must not be re-serialized.
	if want := strings.TrimPrefix(input, "sig1="); entry.Source != want {
		t.Errorf("source = %q, want %q", entry.Source, want)
	}
}

func TestDictionarySourceExcludesSurroundings(t *testing.T) {
	dict, err := ParseDictionary(`a=1 ,  b=("x");y=2  `)
	if err != nil {
		t.Fatalf("ParseDictionary: %v", err)
	}
	a, _ := dict.Get("a")
	if a.Source != "1" {
		t.Errorf("a source = %q", a.Source)
	}
	b, _ := dict.Get("b")
	if b.Source != `("x");y=2` {
		t.Errorf("b source = %q", b.Source)
	}
}

func TestDictionaryDuplicateKeyTakesNewPosition(t *testing.T) {
	dict, err := ParseDictionary("a=1, b=2, a=3")
	if err != nil {
		t.Fatalf("ParseDictionary: %v", err)
	}
	a, _ := dict.Get("a")
	if a.Source != "3" {
		t.Errorf("later duplicate should win, got %q", a.Source)
	}
	if got := strings.Join(dict.Keys(), ","); got != "b,a" {
		t.Errorf("key order = %q, want b,a", got)
	}
}

func TestParseDictionaryRejects(t *testing.T) {
	for _, input := range []string{"Sig1=1", "1sig=1", "a=1,", "a=1 b=2", `a=("x") ;y=2`} {
		if _, err := ParseDictionary(input); err == nil {
			t.Errorf("ParseDictionary(%q) should have failed", input)
		}
	}
}

func TestParseListRejects(t *testing.T) {
	for _, input := range []string{"a, b,", `("a" "b") 42`, `("a"`, `("a", "b")`} {
		if _, err := ParseList(input); err == nil {
			t.Errorf("ParseList(%q) should have failed", input)
		}
	}
}

func TestParseErrorReportsOffset(t *testing.T) {
	_, err := ParseDictionary("a=1, !bad=2")
	perr, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("expected a ParseError, got %T", err)
	}
	if perr.Position != 5 {
		t.Errorf("position = %d, want 5", perr.Position)
	}
}

func TestRoundTrip(t *testing.T) {
	for _, input := range []string{
		"42", "-42", "4.5", `"hi"`, "ed25519", "?1", "@1659578233", ":aGVsbG8=:",
		`%"caf%c3%a9"`, `tok;a=1;b;c="x"`,
	} {
		item, err := ParseItem(input)
		if err != nil {
			t.Fatalf("ParseItem(%q): %v", input, err)
		}
		out, err := SerializeItem(item)
		if err != nil {
			t.Fatalf("SerializeItem(%q): %v", input, err)
		}
		if out != input {
			t.Errorf("round trip %q -> %q", input, out)
		}
	}
}

func TestRoundTripDictionary(t *testing.T) {
	const input = `sig1=("@authority" "signature-agent");created=1735689600;expires=1735689660` +
		`;keyid="abc";alg="ed25519";tag="web-bot-auth"`
	dict, err := ParseDictionary(input)
	if err != nil {
		t.Fatalf("ParseDictionary: %v", err)
	}
	out, err := SerializeDictionary(dict)
	if err != nil {
		t.Fatalf("SerializeDictionary: %v", err)
	}
	if out != input {
		t.Errorf("round trip mismatch:\n got %q\nwant %q", out, input)
	}
}

func TestSerializeElidesBooleanTrue(t *testing.T) {
	dict, err := ParseDictionary("a, b=?0")
	if err != nil {
		t.Fatalf("ParseDictionary: %v", err)
	}
	out, err := SerializeDictionary(dict)
	if err != nil {
		t.Fatalf("SerializeDictionary: %v", err)
	}
	if out != "a, b=?0" {
		t.Errorf("got %q", out)
	}
}

func TestSerializeRejectsInvalid(t *testing.T) {
	cases := []BareItem{
		{Kind: KindInteger, Int: 1e16},
		{Kind: KindString, Str: "café"},
		{Kind: KindToken, Str: "1nope"},
	}
	for _, item := range cases {
		if _, err := SerializeBareItem(item); err == nil {
			t.Errorf("SerializeBareItem(%v) should have failed", item)
		}
	}
}
