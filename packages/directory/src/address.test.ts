import { describe, expect, it } from 'vitest'
import { isPublicAddress, parseIPv4, parseIPv6 } from './address.js'

describe('isPublicAddress', () => {
  it.each([
    '1.1.1.1',
    '8.8.8.8',
    '93.184.216.34',
    '2606:4700:4700::1111',
    '2a00:1450:4001:80f::200e',
  ])('accepts the public address %s', (ip) => {
    expect(isPublicAddress(ip)).toBe(true)
  })

  it.each([
    ['loopback', '127.0.0.1'],
    ['loopback, non-obvious form', '127.1.2.3'],
    ['this network', '0.0.0.0'],
    ['private 10/8', '10.0.0.1'],
    ['private 172.16/12 lower edge', '172.16.0.1'],
    ['private 172.16/12 upper edge', '172.31.255.254'],
    ['private 192.168/16', '192.168.1.1'],
    ['carrier-grade NAT', '100.64.0.1'],
    ['link-local', '169.254.1.1'],
    ['broadcast', '255.255.255.255'],
    ['multicast', '224.0.0.1'],
    ['benchmarking', '198.18.0.1'],
    ['IPv6 loopback', '::1'],
    ['IPv6 unspecified', '::'],
    ['IPv6 unique local', 'fd00::1'],
    ['IPv6 link-local', 'fe80::1'],
    ['IPv6 multicast', 'ff02::1'],
    ['IPv6 documentation', '2001:db8::1'],
  ])('refuses %s', (_label, ip) => {
    expect(isPublicAddress(ip)).toBe(false)
  })

  // The single address this guard exists for.
  it('refuses the cloud metadata endpoint', () => {
    expect(isPublicAddress('169.254.169.254')).toBe(false)
  })

  // An IPv4-mapped or NAT64-embedded loopback is the classic way past a guard
  // that only inspects the textual form.
  it.each(['::ffff:127.0.0.1', '::ffff:169.254.169.254', '::127.0.0.1', '64:ff9b::127.0.0.1'])(
    'refuses %s by judging the embedded IPv4 address',
    (ip) => {
      expect(isPublicAddress(ip)).toBe(false)
    },
  )

  it('still accepts an IPv4-mapped public address', () => {
    expect(isPublicAddress('::ffff:1.1.1.1')).toBe(true)
  })

  // Anything we cannot classify, we cannot vouch for.
  it.each(['', 'not-an-ip', '1.2.3', '1.2.3.4.5', '256.1.1.1', 'gg::1', '::1::2', '1.2.3.-1'])(
    'refuses unparseable input %s',
    (ip) => {
      expect(isPublicAddress(ip)).toBe(false)
    },
  )

  // Leading zeros are read as octal by some resolvers and decimal by others,
  // so 0177.0.0.1 could reach loopback on one stack and not another.
  it('refuses ambiguous leading-zero octets', () => {
    expect(isPublicAddress('010.0.0.1')).toBe(false)
    expect(isPublicAddress('0177.0.0.1')).toBe(false)
  })
})

describe('parseIPv4', () => {
  it('parses a dotted quad', () => {
    expect([...(parseIPv4('192.168.0.1') as Uint8Array)]).toEqual([192, 168, 0, 1])
  })

  it.each(['1.2.3', '1.2.3.4.5', '256.0.0.1', '01.2.3.4', '', 'a.b.c.d'])('rejects %s', (value) => {
    expect(parseIPv4(value)).toBeUndefined()
  })
})

describe('parseIPv6', () => {
  it('expands ::', () => {
    expect([...(parseIPv6('::1') as Uint8Array)]).toEqual([...new Array<number>(15).fill(0), 1])
  })

  it('parses a full address', () => {
    const bytes = parseIPv6('2001:0db8:0000:0000:0000:0000:0000:0001') as Uint8Array
    expect(bytes[0]).toBe(0x20)
    expect(bytes[1]).toBe(0x01)
    expect(bytes[15]).toBe(1)
  })

  it('parses an embedded IPv4 suffix', () => {
    const bytes = parseIPv6('::ffff:192.168.1.1') as Uint8Array
    expect([...bytes.slice(10)]).toEqual([0xff, 0xff, 192, 168, 1, 1])
  })

  it('ignores a zone identifier', () => {
    expect(parseIPv6('fe80::1%eth0')).toBeDefined()
  })

  it.each(['::1::2', 'gg::1', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '::1.2.3'])(
    'rejects %s',
    (value) => {
      expect(parseIPv6(value)).toBeUndefined()
    },
  )
})
