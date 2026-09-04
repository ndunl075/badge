/**
 * Address classification for the SSRF guard.
 *
 * `Signature-Agent` is attacker-controlled and Badge fetches a URL derived from
 * it, so an unconstrained client is a request forger pointed at whatever the
 * caller names — a cloud metadata endpoint, an internal admin panel, a database
 * on the same subnet. This module decides what "public" means, and it is
 * deliberately a denylist of everything special rather than an allowlist of
 * what looks routable: new special-purpose ranges get added, and failing closed
 * on an address we do not recognize would break the open internet instead.
 */

/** IPv4 ranges that must never be fetched. Sources: RFC 1918, 5735, 5737, 6598, 3927. */
const BLOCKED_V4: readonly (readonly [string, number])[] = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, including cloud metadata at 169.254.169.254
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, includes 255.255.255.255
]

export function parseIPv4(value: string): Uint8Array | undefined {
  const parts = value.split('.')
  if (parts.length !== 4) return undefined
  const bytes = new Uint8Array(4)
  for (let i = 0; i < 4; i += 1) {
    const part = parts[i] as string
    // Reject empty, oversized, and leading-zero forms: 010.0.0.1 is parsed as
    // octal by some resolvers and as decimal by others.
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return undefined
    const n = Number(part)
    if (n > 255) return undefined
    bytes[i] = n
  }
  return bytes
}

export function parseIPv6(value: string): Uint8Array | undefined {
  const zone = value.indexOf('%')
  const address = zone === -1 ? value : value.slice(0, zone)
  const halves = address.split('::')
  if (halves.length > 2) return undefined

  const expand = (group: string): string[] => (group === '' ? [] : group.split(':'))
  const head = expand(halves[0] as string)
  const tail = halves.length === 2 ? expand(halves[1] as string) : []

  const bytes: number[] = []
  const pushGroups = (groups: readonly string[], out: number[]): boolean => {
    for (const [i, group] of groups.entries()) {
      // A trailing IPv4 form, e.g. ::ffff:192.168.1.1
      if (group.includes('.')) {
        if (i !== groups.length - 1) return false
        const v4 = parseIPv4(group)
        if (v4 === undefined) return false
        out.push(...v4)
        continue
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return false
      const n = Number.parseInt(group, 16)
      out.push(n >> 8, n & 0xff)
    }
    return true
  }

  const headBytes: number[] = []
  const tailBytes: number[] = []
  if (!pushGroups(head, headBytes)) return undefined
  if (!pushGroups(tail, tailBytes)) return undefined

  if (halves.length === 1) {
    if (headBytes.length !== 16) return undefined
    return new Uint8Array(headBytes)
  }
  const gap = 16 - headBytes.length - tailBytes.length
  if (gap < 0) return undefined
  bytes.push(...headBytes, ...new Array<number>(gap).fill(0), ...tailBytes)
  return new Uint8Array(bytes)
}

function inV4Range(address: Uint8Array, network: string, prefix: number): boolean {
  const net = parseIPv4(network)
  if (net === undefined) return false
  let bitsLeft = prefix
  for (let i = 0; i < 4 && bitsLeft > 0; i += 1) {
    const bits = Math.min(8, bitsLeft)
    const mask = (0xff << (8 - bits)) & 0xff
    if (((address[i] as number) & mask) !== ((net[i] as number) & mask)) return false
    bitsLeft -= bits
  }
  return true
}

function isPublicV4(address: Uint8Array): boolean {
  return !BLOCKED_V4.some(([network, prefix]) => inV4Range(address, network, prefix))
}

function isPublicV6(address: Uint8Array): boolean {
  const [b0, b1] = [address[0] as number, address[1] as number]

  // Unspecified (::) and loopback (::1)
  if (address.every((b, i) => (i === 15 ? b === 0 || b === 1 : b === 0))) return false
  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible: judge the embedded address.
  const firstTwelveZero = address.slice(0, 10).every((b) => b === 0)
  if (firstTwelveZero && address[10] === 0xff && address[11] === 0xff) {
    return isPublicV4(address.slice(12))
  }
  if (firstTwelveZero && address[10] === 0 && address[11] === 0) {
    return isPublicV4(address.slice(12))
  }
  // 64:ff9b::/96 NAT64 — judge the embedded IPv4 address.
  if (b0 === 0x00 && b1 === 0x64 && address[2] === 0xff && address[3] === 0x9b) {
    return isPublicV4(address.slice(12))
  }
  if ((b0 & 0xfe) === 0xfc) return false // fc00::/7 unique local
  if (b0 === 0xfe && (b1 & 0xc0) === 0x80) return false // fe80::/10 link-local
  if (b0 === 0xff) return false // ff00::/8 multicast
  if (b0 === 0x20 && b1 === 0x01 && address[2] === 0x0d && address[3] === 0xb8) return false // 2001:db8::/32
  return true
}

/**
 * Whether an IP literal is safe to connect to.
 *
 * Unparseable input is *not* public: an address we cannot classify is one we
 * cannot vouch for.
 */
export function isPublicAddress(ip: string): boolean {
  const v4 = parseIPv4(ip)
  if (v4 !== undefined) return isPublicV4(v4)
  const v6 = parseIPv6(ip)
  if (v6 !== undefined) return isPublicV6(v6)
  return false
}
