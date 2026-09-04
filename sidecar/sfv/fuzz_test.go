package sfv

import (
	"strings"
	"testing"
)

// Structured fields are the outermost attack surface of a verifier, reached
// before any signature check, on input an attacker fully controls. The parser
// must never panic, hang, or read out of bounds on any input at all.
//
// Go's native fuzzer explores that far better than hand-written cases do. The
// seeds are the interesting shapes: the real Signature-Input, every bare item
// type, and the malformed inputs earlier tests found by hand.

var fuzzSeeds = []string{
	`sig1=("@authority" "signature-agent");created=1735689600;expires=1735689660;keyid="abc";alg="ed25519";tag="web-bot-auth"`,
	`sig1=:aGVsbG8=:`,
	`a=1, b=2, a=3`,
	`a`,
	`a;b;c=1`,
	`("a" "b");x=1`,
	`%"caf%c3%a9"`,
	`@1659578233`,
	`4.567`,
	`-0.0`,
	`tok:with/slashes`,
	`"escaped \" and \\"`,
	``,
	`,`,
	`(`,
	`:`,
	`"`,
	`%`,
	`?`,
	`@`,
	`a=(`,
	`a=)`,
	`::::`,
	`%"%"`,
	`%"%zz"`,
	strings.Repeat("a=1, ", 200),
	strings.Repeat("(", 200),
	strings.Repeat(";a", 200),
	`a=` + strings.Repeat("9", 40),
	`a=1.` + strings.Repeat("9", 40),
}

func FuzzParseDictionary(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		dict, err := ParseDictionary(input)
		if err != nil {
			if dict != nil {
				t.Fatalf("a failed parse returned a dictionary")
			}
			return
		}
		// A successful parse must be self-consistent: every advertised key
		// resolves, and nothing claims a source span outside the input.
		for _, key := range dict.Keys() {
			entry, ok := dict.Get(key)
			if !ok {
				t.Fatalf("key %q is listed but not retrievable", key)
			}
			if entry.Source != "" && !strings.Contains(input, entry.Source) {
				t.Fatalf("source %q is not a substring of the input", entry.Source)
			}
		}
	})
}

func FuzzParseItem(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		item, err := ParseItem(input)
		if err != nil {
			return
		}
		// Anything that parses must serialize, and re-parsing that must give
		// the same value. A round trip that loses information is a way for two
		// implementations to disagree about what was signed.
		serialized, err := SerializeItem(item)
		if err != nil {
			// Display strings and decimals have serialization constraints the
			// parser does not enforce; a refusal is acceptable, a panic is not.
			return
		}
		again, err := ParseItem(serialized)
		if err != nil {
			t.Fatalf("re-parsing our own output failed: %q -> %q: %v", input, serialized, err)
		}
		if again.Value.Kind != item.Value.Kind {
			t.Fatalf("round trip changed the kind: %q -> %v then %v", input, item.Value.Kind, again.Value.Kind)
		}
		if again.Value.Str != item.Value.Str || again.Value.Int != item.Value.Int {
			t.Fatalf("round trip changed the value: %q", input)
		}
	})
}

func FuzzParseList(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if _, err := ParseList(input); err != nil {
			return
		}
	})
}
