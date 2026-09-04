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
    it.each(['"content-digest";sf', '"x-multi";key="a"', '"@authority";req'])(
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
