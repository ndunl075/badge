import { describe, expect, it } from 'vitest'
import { parseDictionary, parseItem, parseList } from './parse.js'
import { SfParseError } from './types.js'

describe('parseItem', () => {
  it('parses each bare item type distinctly', () => {
    expect(parseItem('42').value).toEqual({ type: 'integer', value: 42 })
    expect(parseItem('-42').value).toEqual({ type: 'integer', value: -42 })
    expect(parseItem('4.5').value).toEqual({ type: 'decimal', value: 4.5 })
    expect(parseItem('"hi"').value).toEqual({ type: 'string', value: 'hi' })
    expect(parseItem('foo123/456').value).toEqual({ type: 'token', value: 'foo123/456' })
    expect(parseItem('?1').value).toEqual({ type: 'boolean', value: true })
    expect(parseItem('?0').value).toEqual({ type: 'boolean', value: false })
    expect(parseItem('@1659578233').value).toEqual({ type: 'date', value: 1659578233 })
  })

  // The one distinction Badge most depends on: tag="web-bot-auth" is a String.
  // A Token that happens to spell the same thing must not compare equal.
  it('keeps tokens and strings apart', () => {
    expect(parseItem('"web-bot-auth"').value.type).toBe('string')
    expect(parseItem('web-bot-auth').value.type).toBe('token')
  })

  it('decodes byte sequences', () => {
    const item = parseItem(':aGVsbG8=:')
    expect(item.value.type).toBe('binary')
    if (item.value.type !== 'binary') throw new Error('unreachable')
    expect(new TextDecoder().decode(item.value.value)).toBe('hello')
  })

  it('decodes display strings from percent-encoded UTF-8', () => {
    expect(parseItem('%"caf%c3%a9"').value).toEqual({ type: 'displaystring', value: 'café' })
  })

  it('handles string escapes', () => {
    expect(parseItem('"a\\"b\\\\c"').value).toEqual({ type: 'string', value: 'a"b\\c' })
  })

  it('parses parameters in order, with bare parameters defaulting to true', () => {
    const item = parseItem('token;a=1;b;c="x"')
    expect([...item.params.keys()]).toEqual(['a', 'b', 'c'])
    expect(item.params.get('b')).toEqual({ type: 'boolean', value: true })
  })

  it.each([
    ['unterminated string', '"abc'],
    ['bad escape', '"a\\nb"'],
    ['trailing junk', '42 43'],
    ['bare decimal point', '4.'],
    ['four fractional digits', '4.5678'],
    ['sixteen integer digits', '1234567890123456'],
    ['non-lowercase percent escape', '%"caf%C3%A9"'],
    ['unterminated byte sequence', ':aGVsbG8='],
    ['non-base64 byte sequence', ':not base64!:'],
    ['empty input', ''],
    ['date with a fraction', '@165957.5'],
  ])('rejects %s', (_label, input) => {
    expect(() => parseItem(input)).toThrow(SfParseError)
  })
})

describe('parseList', () => {
  it('parses inner lists with parameters', () => {
    const list = parseList('("a" "b");x=1, 42')
    expect(list).toHaveLength(2)
    const first = list[0]
    if (first?.kind !== 'inner-list') throw new Error('expected inner list')
    expect(first.items.map((i) => i.value)).toEqual([
      { type: 'string', value: 'a' },
      { type: 'string', value: 'b' },
    ])
    expect(first.params.get('x')).toEqual({ type: 'integer', value: 1 })
  })

  it.each([
    ['a trailing comma', 'a, b,'],
    ['a missing separator', '("a" "b") 42'],
    ['an unterminated inner list', '("a"'],
    ['a comma inside an inner list', '("a", "b")'],
  ])('rejects %s', (_label, input) => {
    expect(() => parseList(input)).toThrow(SfParseError)
  })
})

describe('parseDictionary', () => {
  const signatureInput =
    'sig1=("@authority" "signature-agent");created=1735689600;expires=1735689660' +
    ';keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";tag="web-bot-auth"'

  it('parses a realistic Signature-Input', () => {
    const dict = parseDictionary(signatureInput)
    const entry = dict.get('sig1')
    if (entry?.value.kind !== 'inner-list') throw new Error('expected inner list')
    expect(entry.value.items.map((i) => i.value)).toEqual([
      { type: 'string', value: '@authority' },
      { type: 'string', value: 'signature-agent' },
    ])
    expect(entry.value.params.get('tag')).toEqual({ type: 'string', value: 'web-bot-auth' })
    expect(entry.value.params.get('created')).toEqual({ type: 'integer', value: 1735689600 })
  })

  // This is the whole reason DictionaryEntry carries `source`: the signer's own
  // bytes are what it signed over, so we must not re-serialize them.
  it('captures the exact received bytes of each member', () => {
    const dict = parseDictionary(signatureInput)
    expect(dict.get('sig1')?.source).toBe(signatureInput.slice('sig1='.length))
  })

  it('excludes surrounding whitespace and separators from the source span', () => {
    const dict = parseDictionary('a=1 ,  b=("x");y=2  ')
    expect(dict.get('a')?.source).toBe('1')
    expect(dict.get('b')?.source).toBe('("x");y=2')
  })

  it('treats a valueless key as boolean true', () => {
    const dict = parseDictionary('a, b=2')
    const a = dict.get('a')
    if (a?.value.kind !== 'item') throw new Error('expected item')
    expect(a.value.value).toEqual({ type: 'boolean', value: true })
  })

  it('lets a later duplicate key replace an earlier one, keeping its new position', () => {
    const dict = parseDictionary('a=1, b=2, a=3')
    expect(dict.get('a')?.source).toBe('3')
    expect([...dict.keys()]).toEqual(['b', 'a'])
  })

  it('parses multiple signatures and preserves order', () => {
    const dict = parseDictionary(
      'sig1=("@authority");tag="other", sig2=("@authority");tag="web-bot-auth"',
    )
    expect([...dict.keys()]).toEqual(['sig1', 'sig2'])
  })

  it.each([
    ['an uppercase key', 'Sig1=1'],
    ['a key starting with a digit', '1sig=1'],
    ['a trailing comma', 'a=1,'],
    ['a missing comma', 'a=1 b=2'],
    ['whitespace before parameters', 'a=("x") ;y=2'],
  ])('rejects %s', (_label, input) => {
    expect(() => parseDictionary(input)).toThrow(SfParseError)
  })

  it('reports the offset of the failure', () => {
    try {
      parseDictionary('a=1, !bad=2')
      expect.unreachable('should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(SfParseError)
      expect((err as SfParseError).position).toBe(5)
    }
  })
})
