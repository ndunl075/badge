import { staticKeyResolver } from '@badge/core'
import { createBadge } from '@badge/middleware'
import type { Policy } from '@badge/policy'
import { fixedClock, generateSigningKey, signRequest, type SigningKey } from '@badge/testkit'
import { beforeAll, describe, expect, it } from 'vitest'
import { badgeFetchMiddleware, badgeHono, fromFetchRequest } from './fetch.js'

const NOW = 1_735_689_600
const ORIGIN = 'https://agent.example'

let key: SigningKey

beforeAll(async () => {
  key = await generateSigningKey()
})

const denyVerified: Policy = {
  version: 1,
  default: 'log-only',
  rules: [{ id: 'no-agents', action: 'deny', when: { status: 'verified' } }],
}

const badge = (policy: Policy) =>
  createBadge({
    policy,
    keys: staticKeyResolver({ [ORIGIN]: [key.publicJwk] }),
    clock: fixedClock(NOW),
    sinks: [],
  })

const signed = async (authority = 'example.com') =>
  await signRequest({ key, created: NOW, expires: NOW + 60, authority })

describe('fromFetchRequest', () => {
  it('takes authority, path and query from the URL', () => {
    const request = fromFetchRequest(new Request('https://example.com/a/b?x=1&y=2'))
    expect(request.authority).toBe('example.com')
    expect(request.scheme).toBe('https')
    expect(request.path).toBe('/a/b')
    expect(request.query).toBe('x=1&y=2')
  })

  it('leaves the query empty when there is none', () => {
    expect(fromFetchRequest(new Request('https://example.com/a')).query).toBe('')
  })

  it('carries headers through', () => {
    const request = fromFetchRequest(
      new Request('https://example.com/', { headers: { 'signature-agent': '"https://a"' } }),
    )
    expect(request.header('signature-agent')).toBe('"https://a"')
  })

  it('ignores forwarding headers unless configured to trust them', () => {
    const request = fromFetchRequest(
      new Request('https://real.example/', {
        headers: { 'x-forwarded-host': 'attacker.example' },
      }),
    )
    expect(request.authority).toBe('real.example')
  })

  it('uses the forwarded host when told to', () => {
    const request = fromFetchRequest(
      new Request('https://internal.example/', {
        headers: { 'x-forwarded-host': 'public.example' },
      }),
      { authority: 'forwarded' },
    )
    expect(request.authority).toBe('public.example')
  })
})

describe('badgeFetchMiddleware', () => {
  it('calls through on allow', async () => {
    const middleware = badgeFetchMiddleware(badge({ version: 1, default: 'log-only' }))
    const response = await middleware(
      new Request('https://example.com/', { headers: (await signed()).headers }),
      async () => new Response('handler reached'),
    )
    expect(await response.text()).toBe('handler reached')
  })

  it('denies without calling the handler', async () => {
    const middleware = badgeFetchMiddleware(badge(denyVerified))
    let called = false
    const response = await middleware(
      new Request('https://example.com/', { headers: (await signed()).headers }),
      async () => {
        called = true
        return new Response('handler reached')
      },
    )
    expect(called).toBe(false)
    expect(response.status).toBe(403)
    expect(response.headers.get('cache-control')).toBe('no-store')
  })

  it('adds debug headers to the downstream response only when asked', async () => {
    const plain = badgeFetchMiddleware(badge({ version: 1, default: 'log-only' }))
    const debug = badgeFetchMiddleware(badge({ version: 1, default: 'log-only' }), {
      debugHeaders: true,
    })
    const headers = (await signed()).headers
    const make = () => new Request('https://example.com/', { headers })
    expect((await plain(make(), async () => new Response('x'))).headers.get('x-badge-reason')).toBe(
      null,
    )
    expect((await debug(make(), async () => new Response('x'))).headers.get('x-badge-reason')).toBe(
      'ok',
    )
  })
})

describe('badgeHono', () => {
  it('lets the handler run on allow', async () => {
    const middleware = badgeHono(badge({ version: 1, default: 'log-only' }))
    let called = false
    const result = await middleware(
      { req: { raw: new Request('https://example.com/', { headers: (await signed()).headers }) } },
      async () => {
        called = true
      },
    )
    expect(called).toBe(true)
    expect(result).toBeUndefined()
  })

  it('short-circuits with a Response on deny', async () => {
    const middleware = badgeHono(badge(denyVerified))
    let called = false
    const result = await middleware(
      { req: { raw: new Request('https://example.com/', { headers: (await signed()).headers }) } },
      async () => {
        called = true
      },
    )
    expect(called).toBe(false)
    expect(result?.status).toBe(403)
  })
})
