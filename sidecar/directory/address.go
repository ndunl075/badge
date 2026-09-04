// Package directory fetches Web Bot Auth key directories, safely.
//
// Signature-Agent is attacker-controlled and the client fetches a URL derived
// from it, so an unconstrained client is a request forger pointed at whatever
// the caller names.
package directory

import "net/netip"

// blocked lists the special-purpose ranges that must never be fetched, from the
// IANA IPv4 and IPv6 Special-Purpose Address Registries.
//
// A denylist of everything special rather than an allowlist of what looks
// routable: new ranges get assigned, and failing closed on an address we do not
// recognize would break the open internet instead.
var blocked = []netip.Prefix{
	// IPv4
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("10.0.0.0/8"),      // private
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local, incl. cloud metadata
	netip.MustParsePrefix("172.16.0.0/12"),   // private
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // deprecated 6to4 relay anycast
	netip.MustParsePrefix("192.168.0.0/16"),  // private
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, incl. broadcast

	// IPv6. The transition mechanisms matter as much as the private ranges:
	// 2002:a9fe:a9fe:: is 6to4 for 169.254.169.254, so an attacker publishing
	// that as an AAAA record reaches the metadata endpoint on any host with a
	// 6to4 path. Both 6to4 and Teredo are deprecated, so they are refused
	// wholesale rather than by picking the embedded address apart.
	netip.MustParsePrefix("::/128"),        // unspecified
	netip.MustParsePrefix("::1/128"),       // loopback
	netip.MustParsePrefix("100::/64"),      // discard-only
	netip.MustParsePrefix("2001::/32"),     // Teredo
	netip.MustParsePrefix("2001:2::/48"),   // benchmarking
	netip.MustParsePrefix("2001:20::/28"),  // ORCHIDv2
	netip.MustParsePrefix("2001:db8::/32"), // documentation
	netip.MustParsePrefix("2002::/16"),     // 6to4
	netip.MustParsePrefix("3fff::/20"),     // documentation
	netip.MustParsePrefix("5f00::/16"),     // segment routing
	netip.MustParsePrefix("fc00::/7"),      // unique local
	netip.MustParsePrefix("fe80::/10"),     // link-local
	netip.MustParsePrefix("ff00::/8"),      // multicast
}

// nat64 embeds an IPv4 address in its low 32 bits.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// IsPublicAddress reports whether an address is safe to connect to.
//
// Anything unparseable is not public: an address we cannot classify is one we
// cannot vouch for.
func IsPublicAddress(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.WithZone("")

	// IPv4-mapped, IPv4-compatible and NAT64 addresses are judged by the IPv4
	// address they embed — the classic way past a guard that only inspects the
	// textual form.
	if addr.Is4In6() {
		return IsPublicAddress(addr.Unmap())
	}
	if nat64.Contains(addr) {
		return IsPublicAddress(embeddedV4(addr))
	}
	if addr.Is6() && isV4Compatible(addr) {
		return IsPublicAddress(embeddedV4(addr))
	}

	for _, prefix := range blocked {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// ParsePublicAddress parses a textual address and reports whether it is public.
func ParsePublicAddress(text string) bool {
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return false
	}
	return IsPublicAddress(addr)
}

func embeddedV4(addr netip.Addr) netip.Addr {
	b := addr.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
}

// isV4Compatible matches ::a.b.c.d, the deprecated IPv4-compatible form, which
// netip does not classify as 4-in-6.
func isV4Compatible(addr netip.Addr) bool {
	b := addr.As16()
	for i := 0; i < 12; i++ {
		if b[i] != 0 {
			return false
		}
	}
	// ::0 and ::1 are the unspecified and loopback addresses, handled by the
	// prefix table above.
	return !(b[12] == 0 && b[13] == 0 && b[14] == 0 && b[15] <= 1)
}
