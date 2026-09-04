import { describe, expect, it } from 'vitest'
import { SignatureBaseError, buildSignatureBase } from './base.js'
import { createRequest } from './request.js'
import { parseDictionary, parseItem } from './sfv/parse.js'
import type { Item } from './sfv/types.js'

const request = createRequest({
  method: 'get',
  scheme: 'https',
  authority: 'Example.COM',
  path: '/docs/intro',
  query: 'a=1&b=hello%20world',
  headers: {
    'signature-agent': '"https://agent.example"',
    'x-multi': ['one', 'two'],
    'x-padded': '   spaced   ',
  },
})

const components = (...ids: string[]): Item[] => ids.map((id) => parseItem(id))

describe('component parameters', () => {
  const withHeaders = (headers: Record<string, string | string[]>) =>
    createRequest({
      method: 'GET',
      scheme: 'https',
      authority: 'example.com',
      path: '/',
      headers,
    })

  const line = (
    id: string,
    headers: Record<string, string | string[]>,
    types?: Record<string, 'dictionary' | 'list' | 'item'>,
  ): string => {
    const base = buildSignatureBase({
      request: withHeaders(headers),
      components: [parseItem(id)],
      signatureParamsSource: '()',
      ...(types === undefined ? {} : { structuredFieldTypes: types }),
    })
    return base.split('\n')[0] as string
  }

  describe(';sf re-serializes strictly', () => {
    it('normalizes a dictionary field', () => {
      expect(
        line('"content-digest";sf', { 'content-digest': 'sha-256=:YWJj:,   sha-512=:ZGVm:' }),
      ).toBe('"content-digest";sf: sha-256=:YWJj:, sha-512=:ZGVm:')
    })

    it('normalizes a list field', () => {
      expect(line('"accept";sf', { accept: 'text/html ,  application/json;q=0.9' })).toBe(
        '"accept";sf: text/html, application/json;q=0.9',
      )
    })

    it('normalizes an item field', () => {
      expect(line('"content-length";sf', { 'content-length': '  42 ' })).toBe(
        '"content-length";sf: 42',
      )
    })

    // Canonicalizing under the wrong type would produce a different base and so
    // a signature_invalid verdict: a well-behaved caller reported as hostile.
    // Refusing is the only safe answer for a field we do not know.
    it('refuses a field whose structured type it does not know', () => {
      expect(() => line('"x-custom";sf', { 'x-custom': 'a=1' })).toThrow(SignatureBaseError)
    })

    it('accepts a type the operator supplied', () => {
      expect(line('"x-custom";sf', { 'x-custom': 'a=1,  b=2' }, { 'x-custom': 'dictionary' })).toBe(
        '"x-custom";sf: a=1, b=2',
      )
    })

    // A distinct code from covered_component_missing: an operator reading that
    // one goes looking for an absent header, and this header was present.
    it('reports a present field that is not a valid structured field', () => {
      try {
        line('"content-digest";sf', { 'content-digest': 'not a dictionary!' })
        expect.unreachable('should have thrown')
      } catch (err) {
        expect((err as SignatureBaseError).reason).toBe('covered_field_not_structured')
      }
    })

    /**
     * A header literally named `constructor` resolves through the prototype
     * chain to a truthy value on an object literal, slipping past the
     * unknown-type guard and canonicalizing under a guessed type — the exact
     * outcome the type map exists to prevent.
     */
    it.each(['constructor', '__proto__', 'tostring'])(
      'does not resolve the field name %s through the prototype chain',
      (name) => {
        expect(() => line(`"${name}";sf`, { [name]: 'a=1' })).toThrow(SignatureBaseError)
      },
    )

    // RFC 9651 lets a signer write ;sf=?0, which means the flag is off.
    // Canonicalizing anyway would change the base and libel a well-behaved signer.
    it('treats ;sf=?0 as not set', () => {
      expect(
        line('"cache-control";sf=?0', { 'cache-control': 'max-age=60,  must-revalidate' }),
      ).toBe('"cache-control";sf=?0: max-age=60,  must-revalidate')
    })

    it('rejects a non-boolean ;sf', () => {
      try {
        line('"cache-control";sf="yes"', { 'cache-control': 'max-age=60' })
        expect.unreachable('should have thrown')
      } catch (err) {
        expect((err as SignatureBaseError).reason).toBe('signature_input_malformed')
      }
    })
  })

  describe(';key selects a dictionary member', () => {
    const headers = { 'content-digest': 'sha-256=:YWJj:, sha-512=:ZGVm:' }

    it('serializes the named member', () => {
      expect(line('"content-digest";key="sha-512"', headers)).toBe(
        '"content-digest";key="sha-512": :ZGVm:',
      )
    })

    // ;key only has meaning for a Dictionary, so it settles the type itself and
    // works on fields absent from the type map.
    it('works without a type map entry', () => {
      expect(line('"x-custom";key="b"', { 'x-custom': 'a=1, b=2' })).toBe('"x-custom";key="b": 2')
    })

    it('reports a member the field does not carry', () => {
      try {
        line('"content-digest";key="sha-1"', headers)
        expect.unreachable('should have thrown')
      } catch (err) {
        expect((err as SignatureBaseError).reason).toBe('covered_component_missing')
      }
    })

    it('rejects a non-string key', () => {
      try {
        line('"content-digest";key=1', headers)
        expect.unreachable('should have thrown')
      } catch (err) {
        expect((err as SignatureBaseError).reason).toBe('signature_input_malformed')
      }
    })
  })

  describe(';bs encodes each value separately', () => {
    // RFC 9421 §2.1.3 worked example.
    it('matches the RFC example', () => {
      expect(
        line('"example-header";bs', { 'example-header': ['value, with, lots', 'of, commas'] }),
      ).toBe('"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:')
    })

    it('handles a single value', () => {
      expect(line('"x-one";bs', { 'x-one': 'abc' })).toBe('"x-one";bs: :YWJj:')
    })

    it('treats ;bs=?0 as not set', () => {
      expect(line('"x-one";bs=?0', { 'x-one': 'abc' })).toBe('"x-one";bs=?0: abc')
    })

    /**
     * Node hands header values over already decoded as latin1, one character
     * per wire byte. Re-encoding as UTF-8 would turn byte 0xE9 into 0xC3 0xA9
     * and produce a base that disagrees with a correct signer.
     */
    it('encodes the field value byte for byte, not as UTF-8', () => {
      expect(line('"x-one";bs', { 'x-one': '\u00e9' })).toBe('"x-one";bs: :6Q==:')
    })

    it('refuses a value whose wire bytes cannot be recovered', () => {
      try {
        line('"x-one";bs', { 'x-one': '\u20ac' })
        expect.unreachable('should have thrown')
      } catch (err) {
        expect((err as SignatureBaseError).reason).toBe('unsupported_component')
      }
    })

    it('trims each value before encoding', () => {
      expect(line('"x-one";bs', { 'x-one': '  abc  ' })).toBe('"x-one";bs: :YWJj:')
    })

    it('reports an absent field', () => {
      try {
        line('"x-missing";bs', {})
        expect.unreachable('should have thrown')
      } catch (err) {
        expect((err as SignatureBaseError).reason).toBe('covered_component_missing')
      }
    })

    // RFC 9421 §2.1.3 makes ;bs mutually exclusive with the parsing parameters.
    it.each(['"x-one";bs;sf', '"x-one";bs;key="a"'])('rejects %s', (id) => {
      try {
        line(id, { 'x-one': 'a=1' })
        expect.unreachable('should have thrown')
      } catch (err) {
        expect((err as SignatureBaseError).reason).toBe('signature_input_malformed')
      }
    })

    // Guessing at a comma split would be wrong: a field value may contain one.
    it('refuses when the adapter cannot expose individual values', () => {
      const request = withHeaders({ 'x-one': 'abc' })
      const withoutValues = { ...request, headerValues: undefined }
      try {
        buildSignatureBase({
          request: withoutValues,
          components: [parseItem('"x-one";bs')],
          signatureParamsSource: '()',
        })
        expect.unreachable('should have thrown')
      } catch (err) {
        expect((err as SignatureBaseError).reason).toBe('unsupported_component')
      }
    })
  })
})

describe('buildSignatureBase', () => {
  it('emits one line per component and no trailing newline', () => {
    const base = buildSignatureBase({
      request,
      components: components('"@authority"', '"signature-agent"'),
      signatureParamsSource: '("@authority" "signature-agent");tag="web-bot-auth"',
    })
    expect(base).toBe(
      '"@authority": example.com\n' +
        '"signature-agent": "https://agent.example"\n' +
        '"@signature-params": ("@authority" "signature-agent");tag="web-bot-auth"',
    )
    expect(base.endsWith('\n')).toBe(false)
  })

  it('uses the received signature params bytes verbatim', () => {
    const source = '("@authority");created=1;expires=2;tag="web-bot-auth"'
    const base = buildSignatureBase({
      request,
      components: components('"@authority"'),
      signatureParamsSource: source,
    })
    expect(base.endsWith(`"@signature-params": ${source}`)).toBe(true)
  })

  it('takes the signature params source straight from a parsed Signature-Input', () => {
    const header = 'sig1=("@authority");created=1;tag="web-bot-auth"'
    const entry = parseDictionary(header).get('sig1')
    if (entry?.value.kind !== 'inner-list') throw new Error('expected inner list')
    const base = buildSignatureBase({
      request,
      components: entry.value.items,
      signatureParamsSource: entry.source,
    })
    expect(base).toBe(
      '"@authority": example.com\n"@signature-params": ("@authority");created=1;tag="web-bot-auth"',
    )
  })

  describe('derived components', () => {
    it.each([
      ['"@method"', 'GET'],
      ['"@authority"', 'example.com'],
      ['"@scheme"', 'https'],
      ['"@path"', '/docs/intro'],
      ['"@query"', '?a=1&b=hello%20world'],
      ['"@request-target"', '/docs/intro?a=1&b=hello%20world'],
      ['"@target-uri"', 'https://example.com/docs/intro?a=1&b=hello%20world'],
    ])('derives %s', (id, expected) => {
      const base = buildSignatureBase({
        request,
        components: components(id),
        signatureParamsSource: '()',
      })
      expect(base.split('\n')[0]).toBe(`${id}: ${expected}`)
    })

    it('lowercases the authority and drops the default port', () => {
      const value = (authority: string, scheme: 'http' | 'https'): string => {
        const base = buildSignatureBase({
          request: createRequest({ method: 'GET', scheme, authority, path: '/' }),
          components: components('"@authority"'),
          signatureParamsSource: '()',
        })
        return base.split('\n')[0] as string
      }
      expect(value('Example.com:443', 'https')).toBe('"@authority": example.com')
      expect(value('example.com:80', 'http')).toBe('"@authority": example.com')
      expect(value('example.com:8443', 'https')).toBe('"@authority": example.com:8443')
    })

    it('emits "?" for an absent query', () => {
      const base = buildSignatureBase({
        request: createRequest({ method: 'GET', scheme: 'https', authority: 'e.com', path: '/' }),
        components: components('"@query"'),
        signatureParamsSource: '()',
      })
      expect(base.split('\n')[0]).toBe('"@query": ?')
    })

    it('percent-decodes a query parameter', () => {
      const base = buildSignatureBase({
        request,
        components: components('"@query-param";name="b"'),
        signatureParamsSource: '()',
      })
      expect(base.split('\n')[0]).toBe('"@query-param";name="b": hello world')
    })
  })

  describe('field components', () => {
    it('joins repeated fields with ", " in order', () => {
      const base = buildSignatureBase({
        request,
        components: components('"x-multi"'),
        signatureParamsSource: '()',
      })
      expect(base.split('\n')[0]).toBe('"x-multi": one, two')
    })

    it('strips surrounding whitespace', () => {
      const base = buildSignatureBase({
        request,
        components: components('"x-padded"'),
        signatureParamsSource: '()',
      })
      expect(base.split('\n')[0]).toBe('"x-padded": spaced')
    })
  })

  describe('failures', () => {
    const failsWith = (ids: string[], reason: string): void => {
      try {
        buildSignatureBase({
          request,
          components: components(...ids),
          signatureParamsSource: '()',
        })
        expect.unreachable('should have thrown')
      } catch (err) {
        expect(err).toBeInstanceOf(SignatureBaseError)
        expect((err as SignatureBaseError).reason).toBe(reason)
      }
    }

    // Their mistake: they signed something they did not send.
    it('reports a covered field the request does not carry', () => {
      failsWith(['"content-digest"'], 'covered_component_missing')
    })

    it('reports a covered query parameter the request does not carry', () => {
      failsWith(['"@query-param";name="missing"'], 'covered_component_missing')
    })

    // Our gap: a real spec feature we have not implemented. Calling this
    // untrusted would libel a well-behaved caller.
    it.each(['"@authority";req', '"x-multi";tr', '"x-multi";sf'])(
      'reports %s as our own gap, not as hostile',
      (id) => {
        failsWith([id], 'unsupported_component')
      },
    )

    it('refuses a repeated query parameter rather than guessing', () => {
      const dup = createRequest({
        method: 'GET',
        scheme: 'https',
        authority: 'e.com',
        path: '/',
        query: 'a=1&a=2',
      })
      try {
        buildSignatureBase({
          request: dup,
          components: components('"@query-param";name="a"'),
          signatureParamsSource: '()',
        })
        expect.unreachable('should have thrown')
      } catch (err) {
        expect((err as SignatureBaseError).reason).toBe('unsupported_component')
      }
    })

    it('rejects response-only components in a request', () => {
      failsWith(['"@status"'], 'unsupported_component')
    })

    it('rejects an unknown derived component', () => {
      failsWith(['"@nope"'], 'unsupported_component')
    })

    it('rejects a non-lowercase component identifier', () => {
      failsWith(['"@Authority"'], 'signature_input_malformed')
    })

    it('rejects a duplicate covered component', () => {
      failsWith(['"@authority"', '"@authority"'], 'signature_input_malformed')
    })

    it('rejects a non-string component identifier', () => {
      failsWith(['42'], 'signature_input_malformed')
    })

    it('rejects @query-param without a name', () => {
      failsWith(['"@query-param"'], 'signature_input_malformed')
    })
  })
})
