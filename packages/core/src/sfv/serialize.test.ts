import { describe, expect, it } from 'vitest'
import { parseDictionary, parseItem } from './parse.js'
import {
  SfSerializeError,
  serializeBareItem,
  serializeDictionary,
  serializeInnerList,
  serializeItem,
  sf,
} from './serialize.js'
import type { Member } from './types.js'

describe('serializeBareItem', () => {
  it('serializes each type', () => {
    expect(serializeBareItem(sf.integer(42))).toBe('42')
    expect(serializeBareItem(sf.integer(-42))).toBe('-42')
    expect(serializeBareItem(sf.decimal(4.5))).toBe('4.5')
    expect(serializeBareItem(sf.decimal(4))).toBe('4.0')
    expect(serializeBareItem(sf.string('hi'))).toBe('"hi"')
    expect(serializeBareItem(sf.token('ed25519'))).toBe('ed25519')
    expect(serializeBareItem(sf.boolean(true))).toBe('?1')
    expect(serializeBareItem(sf.boolean(false))).toBe('?0')
    expect(serializeBareItem(sf.date(1659578233))).toBe('@1659578233')
    expect(serializeBareItem(sf.binary(new TextEncoder().encode('hello')))).toBe(':aGVsbG8=:')
    expect(serializeBareItem(sf.displayString('café'))).toBe('%"caf%c3%a9"')
  })

  it('escapes strings', () => {
    expect(serializeBareItem(sf.string('a"b\\c'))).toBe('"a\\"b\\\\c"')
  })

  it.each([
    ['a non-integral integer', sf.integer(1.5)],
    ['an out-of-range integer', sf.integer(10 ** 16)],
    ['a non-ASCII string', sf.string('café')],
    ['an invalid token', sf.token('1nope')],
  ])('rejects %s', (_label, item) => {
    expect(() => serializeBareItem(item)).toThrow(SfSerializeError)
  })

  it('rounds decimals to three fractional digits', () => {
    expect(serializeBareItem(sf.decimal(1.23456))).toBe('1.235')
  })
})

describe('serialize / parse round trip', () => {
  const cases = [
    '42',
    '-42',
    '4.5',
    '"hi"',
    'ed25519',
    '?1',
    '@1659578233',
    ':aGVsbG8=:',
    '%"caf%c3%a9"',
    'tok;a=1;b;c="x"',
  ]

  it.each(cases)('round trips %s', (input) => {
    expect(serializeItem(parseItem(input))).toBe(input)
  })

  it('round trips a realistic Signature-Input member', () => {
    const input =
      'sig1=("@authority" "signature-agent");created=1735689600;expires=1735689660' +
      ';keyid="abc";alg="ed25519";tag="web-bot-auth"'
    const dict = parseDictionary(input)
    const rebuilt = new Map<string, Member>()
    for (const [key, entry] of dict) rebuilt.set(key, entry.value)
    expect(serializeDictionary(rebuilt)).toBe(input)
  })
})

describe('serializeDictionary', () => {
  it('elides "=?1" for boolean-true members', () => {
    const dict = new Map<string, Member>([
      ['a', sf.item(sf.boolean(true))],
      ['b', sf.item(sf.boolean(false))],
    ])
    expect(serializeDictionary(dict)).toBe('a, b=?0')
  })
})

describe('serializeInnerList', () => {
  it('separates items with a single space', () => {
    const list = sf.innerList(
      [sf.item(sf.string('@authority')), sf.item(sf.string('signature-agent'))],
      new Map([['tag', sf.string('web-bot-auth')]]),
    )
    expect(serializeInnerList(list)).toBe('("@authority" "signature-agent");tag="web-bot-auth"')
  })

  it('serializes an empty inner list', () => {
    expect(serializeInnerList(sf.innerList([]))).toBe('()')
  })
})
