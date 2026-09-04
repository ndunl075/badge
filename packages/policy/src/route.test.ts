import { describe, expect, it } from 'vitest'
import { compileRoute, matchesRoute } from './route.js'
import { PolicyError } from './types.js'

const matches = (pattern: string, method: string, path: string): boolean =>
  matchesRoute(compileRoute(pattern), method, path)

describe('route patterns', () => {
  it('matches a method and path', () => {
    expect(matches('GET /docs', 'GET', '/docs')).toBe(true)
    expect(matches('GET /docs', 'POST', '/docs')).toBe(false)
    expect(matches('GET /docs', 'GET', '/other')).toBe(false)
  })

  it('is case-insensitive about the method only', () => {
    expect(matches('get /docs', 'GET', '/docs')).toBe(true)
    expect(matches('GET /docs', 'get', '/docs')).toBe(true)
    expect(matches('GET /Docs', 'GET', '/docs')).toBe(false)
  })

  it('accepts several methods', () => {
    expect(matches('GET|HEAD /docs', 'HEAD', '/docs')).toBe(true)
    expect(matches('GET|HEAD /docs', 'POST', '/docs')).toBe(false)
  })

  it('matches any method when none or "*" is given', () => {
    expect(matches('/docs', 'DELETE', '/docs')).toBe(true)
    expect(matches('* /docs', 'DELETE', '/docs')).toBe(true)
  })

  it('confines * to one segment and lets ** cross them', () => {
    expect(matches('/docs/*', 'GET', '/docs/intro')).toBe(true)
    expect(matches('/docs/*', 'GET', '/docs/a/b')).toBe(false)
    expect(matches('/docs/**', 'GET', '/docs/a/b')).toBe(true)
  })

  // The behaviour people assume, and the one that quietly leaves a hole if it
  // is wrong: /docs/** must cover /docs itself.
  it('lets a trailing /** cover the prefix itself', () => {
    expect(matches('/docs/**', 'GET', '/docs')).toBe(true)
    expect(matches('/docs/**', 'GET', '/docs/')).toBe(true)
    expect(matches('/docs/**', 'GET', '/docsy')).toBe(false)
  })

  it('matches a single character with ?', () => {
    expect(matches('/v?/x', 'GET', '/v1/x')).toBe(true)
    expect(matches('/v?/x', 'GET', '/v12/x')).toBe(false)
  })

  it('treats regex metacharacters in the pattern literally', () => {
    expect(matches('/a.b', 'GET', '/a.b')).toBe(true)
    expect(matches('/a.b', 'GET', '/axb')).toBe(false)
    expect(matches('/a+b', 'GET', '/a+b')).toBe(true)
    expect(matches('/price$', 'GET', '/price$')).toBe(true)
  })

  it('anchors at both ends', () => {
    expect(matches('/docs', 'GET', '/docs/extra')).toBe(false)
    expect(matches('/docs', 'GET', '/prefix/docs')).toBe(false)
  })

  it.each([
    ['an empty pattern', '   '],
    ['a path that does not start with a slash', 'GET docs'],
    ['a method with punctuation', 'GE:T /docs'],
  ])('rejects %s', (_label, pattern) => {
    expect(() => compileRoute(pattern)).toThrow(PolicyError)
  })
})
