import type { Jwk } from '@badge/core'
import { generateSigningKey, fixedClock, type SigningKey } from '@badge/testkit'
import { beforeAll, describe, expect, it } from 'vitest'
import { HttpClientError, type HttpClient, type HttpResponse } from './http.js'
import { createDirectoryResolver } from './resolver.js'

const ORIGIN = 'https://agent.example'
const NOW = 1_735_689_600

let key: SigningKey
let other: SigningKey

beforeAll(async () => {
  ;[key, other] = await Promise.all([generateSigningKey(), generateSigningKey()])
})

interface Recorder extends HttpClient {
  readonly calls: string[]
}

const jwksResponse = (
  keys: readonly Jwk[],
  headers: Record<string, string> = {},
): HttpResponse => ({
  status: 200,
  headers: new Map(
    Object.entries({
      'content-type': 'application/http-message-signatures-directory+json',
      ...headers,
    }),
  ),
  body: new TextEncoder().encode(JSON.stringify({ keys })),
})

const recorder = (
  respond: (url: string, call: number) => HttpResponse | Promise<HttpResponse>,
): Recorder => {
  const calls: string[] = []
  return {
    calls,
    async get(url) {
      calls.push(url)
      return await respond(url, calls.length)
    },
  }
}

const failing = (error: HttpClientError): Recorder => {
  const calls: string[] = []
  return {
    calls,
    async get(url) {
      calls.push(url)
      throw error
    },
  }
}

describe('directory resolver', () => {
  it('fetches the well-known path and finds the key by thumbprint', async () => {
    const http = recorder(() => jwksResponse([key.publicJwk]))
    const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
    const result = await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })
    expect(result).toMatchObject({ ok: true, cache: 'miss' })
    expect(http.calls).toEqual([
      'https://agent.example/.well-known/http-message-signatures-directory',
    ])
  })

  it('reports key_not_found when the directory publishes different keys', async () => {
    const http = recorder(() => jwksResponse([other.publicJwk]))
    const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
    expect(await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })).toMatchObject({
      ok: false,
      reason: 'key_not_found',
    })
  })

  it('does not let one unusable key poison the directory', async () => {
    const http = recorder(() => jwksResponse([{ kty: 'MAGIC' } as Jwk, key.publicJwk]))
    const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
    expect(await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })).toMatchObject({
      ok: true,
    })
  })

  it('serves the second request from cache', async () => {
    const http = recorder(() => jwksResponse([key.publicJwk]))
    const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
    await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })
    const second = await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })
    expect(second).toMatchObject({ cache: 'hit' })
    expect(http.calls).toHaveLength(1)
  })

  it('runs one fetch for concurrent requests to the same origin', async () => {
    let release = (): void => undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const http = recorder(async () => {
      await gate
      return jwksResponse([key.publicJwk])
    })
    const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
    const all = Promise.all(
      Array.from({ length: 5 }, () =>
        resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW }),
      ),
    )
    release()
    for (const result of await all) expect(result).toMatchObject({ ok: true })
    expect(http.calls).toHaveLength(1)
  })

  describe('freshness', () => {
    it('honours max-age within the configured floor and ceiling', async () => {
      const clock = fixedClock(NOW)
      const http = recorder(() => jwksResponse([key.publicJwk], { 'cache-control': 'max-age=120' }))
      const resolver = createDirectoryResolver({ http, clock })
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      clock.advance(119)
      expect(
        await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() }),
      ).toMatchObject({ cache: 'hit' })
      expect(http.calls).toHaveLength(1)
    })

    it('clamps an absurd max-age to the ceiling', async () => {
      const clock = fixedClock(NOW)
      const http = recorder(() =>
        jwksResponse([key.publicJwk], { 'cache-control': 'max-age=31536000' }),
      )
      const resolver = createDirectoryResolver({ http, clock, maxTtlSec: 600 })
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      clock.advance(601)
      expect(
        await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() }),
      ).toMatchObject({ cache: 'stale' })
    })

    // The whole point of the cache: a live request never waits on a refetch it
    // does not strictly need.
    it('serves stale while revalidating behind the request', async () => {
      const clock = fixedClock(NOW)
      const http = recorder(() => jwksResponse([key.publicJwk], { 'cache-control': 'max-age=60' }))
      const resolver = createDirectoryResolver({ http, clock })
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      clock.advance(61)
      const stale = await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      expect(stale).toMatchObject({ ok: true, cache: 'stale' })
      await new Promise((resolve) => setImmediate(resolve))
      expect(http.calls).toHaveLength(2)
    })

    it('refetches once the stale window has also lapsed', async () => {
      const clock = fixedClock(NOW)
      const http = recorder(() => jwksResponse([key.publicJwk], { 'cache-control': 'max-age=60' }))
      const resolver = createDirectoryResolver({ http, clock, staleWhileRevalidateSec: 30 })
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      clock.advance(100)
      expect(
        await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() }),
      ).toMatchObject({ cache: 'miss' })
      expect(http.calls).toHaveLength(2)
    })

    it('treats no-store as immediately stale when the floor allows it', async () => {
      const clock = fixedClock(NOW)
      const http = recorder(() => jwksResponse([key.publicJwk], { 'cache-control': 'no-store' }))
      const resolver = createDirectoryResolver({ http, clock, minTtlSec: 0 })
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      clock.advance(1)
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      expect(http.calls.length).toBeGreaterThan(1)
    })

    /**
     * The floor exists so an origin cannot make Badge fetch its directory on
     * every request — an amplification hazard pointed at us by someone else's
     * configuration. no-store therefore gets the shortest lifetime Badge will
     * use, which is shorter than the default but not zero.
     */
    it('gives no-store the floor rather than the default lifetime', async () => {
      const clock = fixedClock(NOW)
      const http = recorder(() => jwksResponse([key.publicJwk], { 'cache-control': 'no-store' }))
      const resolver = createDirectoryResolver({ http, clock, minTtlSec: 60, defaultTtlSec: 600 })
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })

      clock.advance(59)
      expect(
        await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() }),
      ).toMatchObject({ cache: 'hit' })

      clock.advance(2)
      expect(
        await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() }),
      ).toMatchObject({ cache: 'stale' })
    })

    it('gives a directory with no Cache-Control the default lifetime', async () => {
      const clock = fixedClock(NOW)
      const http = recorder(() => ({
        status: 200,
        headers: new Map([['content-type', 'application/json']]),
        body: new TextEncoder().encode(JSON.stringify({ keys: [key.publicJwk] })),
      }))
      const resolver = createDirectoryResolver({ http, clock, minTtlSec: 60, defaultTtlSec: 600 })
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      clock.advance(120)
      expect(
        await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() }),
      ).toMatchObject({ cache: 'hit' })
    })
  })

  describe('failures', () => {
    it.each([
      ['timeout', 'directory_timeout'],
      ['too-large', 'directory_too_large'],
      ['blocked', 'directory_unreachable'],
      ['network', 'directory_unreachable'],
    ] as const)('maps a %s transport failure to %s', async (kind, reason) => {
      const http = failing(new HttpClientError('nope', kind))
      const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
      expect(await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })).toMatchObject({
        ok: false,
        reason,
      })
    })

    it('treats a non-200 as unreachable', async () => {
      const http = recorder(() => ({ status: 503, headers: new Map(), body: new Uint8Array() }))
      const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
      expect(await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })).toMatchObject({
        reason: 'directory_unreachable',
      })
    })

    it.each([
      ['invalid JSON', new TextEncoder().encode('{oops')],
      ['a missing keys array', new TextEncoder().encode('{"nope":1}')],
      ['keys that are not objects', new TextEncoder().encode('{"keys":["a"]}')],
    ])('treats %s as directory_malformed', async (_label, body) => {
      const http = recorder(() => ({
        status: 200,
        headers: new Map([['content-type', 'application/json']]),
        body,
      }))
      const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
      expect(await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })).toMatchObject({
        reason: 'directory_malformed',
      })
    })

    it('refuses a directory with too many keys', async () => {
      const http = recorder(() => jwksResponse(Array.from({ length: 10 }, () => key.publicJwk)))
      const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW), maxKeys: 5 })
      expect(await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })).toMatchObject({
        reason: 'directory_too_large',
      })
    })

    it('remembers a failure so a broken directory is not hammered', async () => {
      const http = failing(new HttpClientError('down', 'network'))
      const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })
      expect(http.calls).toHaveLength(1)
    })

    it('retries once the negative entry lapses', async () => {
      const clock = fixedClock(NOW)
      const http = failing(new HttpClientError('down', 'network'))
      const resolver = createDirectoryResolver({ http, clock, negativeTtlSec: 10 })
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      clock.advance(11)
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      expect(http.calls).toHaveLength(2)
    })

    it('opens a breaker and then fails without opening a socket', async () => {
      const clock = fixedClock(NOW)
      const http = failing(new HttpClientError('down', 'network'))
      const resolver = createDirectoryResolver({
        http,
        clock,
        negativeTtlSec: 0,
        breakerThreshold: 3,
        breakerResetSec: 60,
      })
      for (let i = 0; i < 3; i += 1) {
        await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
        clock.advance(1)
      }
      expect(http.calls).toHaveLength(3)
      const blocked = await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      expect(blocked).toMatchObject({ reason: 'directory_unreachable', cache: 'miss' })
      expect(http.calls).toHaveLength(3)
    })

    it('closes the breaker again after the reset window', async () => {
      const clock = fixedClock(NOW)
      let fail = true
      const calls: string[] = []
      const http: HttpClient = {
        async get(url) {
          calls.push(url)
          if (fail) throw new HttpClientError('down', 'network')
          return jwksResponse([key.publicJwk])
        },
      }
      const resolver = createDirectoryResolver({
        http,
        clock,
        negativeTtlSec: 0,
        breakerThreshold: 2,
        breakerResetSec: 30,
      })
      for (let i = 0; i < 2; i += 1) {
        await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
        clock.advance(1)
      }
      fail = false
      clock.advance(31)
      expect(
        await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() }),
      ).toMatchObject({ ok: true })
    })
  })

  describe('what the resolver refuses to remember', () => {
    /**
     * The stale window exists to keep serving while an origin is unwell.
     * Overwriting good keys with a 30-second negative entry would throw away
     * the remaining hours of it and hand every caller of that origin an
     * unverifiable verdict, with valid keys sitting in hand.
     */
    it('does not let a failed background refresh evict good stale keys', async () => {
      const clock = fixedClock(NOW)
      let healthy = true
      const http: HttpClient = {
        async get() {
          if (!healthy) throw new HttpClientError('briefly down', 'network')
          return jwksResponse([key.publicJwk], { 'cache-control': 'max-age=60' })
        },
      }
      const resolver = createDirectoryResolver({ http, clock })
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })

      healthy = false
      clock.advance(100)
      expect(
        await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() }),
      ).toMatchObject({ ok: true, cache: 'stale' })
      await new Promise((resolve) => setImmediate(resolve))

      // The refresh failed. The keys are still good and still served.
      expect(
        await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() }),
      ).toMatchObject({ ok: true, cache: 'stale' })
    })

    it('still refreshes stale keys when the origin is healthy', async () => {
      const clock = fixedClock(NOW)
      const http = recorder(() => jwksResponse([key.publicJwk], { 'cache-control': 'max-age=60' }))
      const resolver = createDirectoryResolver({ http, clock })
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      clock.advance(61)
      await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() })
      await new Promise((resolve) => setImmediate(resolve))
      expect(
        await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: clock.now() }),
      ).toMatchObject({ cache: 'hit' })
    })

    /**
     * The concurrency valve is Badge's backpressure, not a fact about the
     * origin. Caching it would let an attacker holding the slots open impose a
     * rolling denial on every legitimate signer whose directory is not already
     * cached.
     */
    it('does not blame an origin it never contacted', async () => {
      let release = (): void => undefined
      const gate = new Promise<void>((resolve) => {
        release = resolve
      })
      let slow = true
      const calls: string[] = []
      const http: HttpClient = {
        async get(url) {
          calls.push(url)
          if (slow) await gate
          return jwksResponse([key.publicJwk])
        },
      }
      const resolver = createDirectoryResolver({
        http,
        clock: fixedClock(NOW),
        maxConcurrentFetches: 1,
      })

      const held = resolver.resolve({ origin: 'https://slow.example', keyid: key.keyid, now: NOW })
      const refused = await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })
      expect(refused).toMatchObject({ ok: false, reason: 'directory_unreachable' })

      release()
      await held
      slow = false

      // The healthy origin is tried, not served a cached blame from before.
      expect(await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })).toMatchObject({
        ok: true,
      })
      expect(calls).toContain(`${ORIGIN}/.well-known/http-message-signatures-directory`)
    })

    /**
     * Breakers are keyed by the attacker-supplied Signature-Agent origin. An
     * unbounded map is a memory-exhaustion primitive, which is why the cache
     * and the in-flight set are bounded too.
     */
    it('bounds the circuit breaker map', async () => {
      const clock = fixedClock(NOW)
      const http = failing(new HttpClientError('down', 'network'))
      const resolver = createDirectoryResolver({
        http,
        clock,
        negativeTtlSec: 0,
        breakerThreshold: 1,
        breakerResetSec: 3600,
        maxBreakers: 2,
      })

      // Trip a breaker for the first origin, then push it out with others.
      for (const host of ['a', 'b', 'c', 'd']) {
        await resolver.resolve({ origin: `https://${host}.example`, keyid: key.keyid, now: NOW })
      }
      const before = http.calls.length

      // Its breaker was evicted, so it is tried again rather than short-circuited.
      await resolver.resolve({ origin: 'https://a.example', keyid: key.keyid, now: NOW })
      expect(http.calls.length).toBe(before + 1)
    })
  })

  describe('egress limits', () => {
    it('never fetches an origin outside the allowlist', async () => {
      const http = recorder(() => jwksResponse([key.publicJwk]))
      const resolver = createDirectoryResolver({
        http,
        clock: fixedClock(NOW),
        allowedOrigins: ['https://known.example'],
      })
      expect(await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })).toMatchObject({
        reason: 'signature_agent_not_allowed',
      })
      expect(http.calls).toHaveLength(0)
    })

    // An attacker naming thousands of origins must not convert request
    // concurrency into unbounded outbound fan-out.
    it('caps the number of origins fetched at once', async () => {
      let release = (): void => undefined
      const gate = new Promise<void>((resolve) => {
        release = resolve
      })
      const http = recorder(async () => {
        await gate
        return jwksResponse([key.publicJwk])
      })
      const resolver = createDirectoryResolver({
        http,
        clock: fixedClock(NOW),
        maxConcurrentFetches: 2,
      })
      const results = Promise.all(
        Array.from({ length: 5 }, (_, i) =>
          resolver.resolve({ origin: `https://a${i}.example`, keyid: key.keyid, now: NOW }),
        ),
      )
      release()
      const settled = await results
      expect(http.calls.length).toBeLessThanOrEqual(2)
      expect(settled.filter((r) => !r.ok)).not.toHaveLength(0)
    })

    it('resolves nothing when no origin was claimed', async () => {
      const http = recorder(() => jwksResponse([key.publicJwk]))
      const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
      expect(
        await resolver.resolve({ origin: undefined, keyid: key.keyid, now: NOW }),
      ).toMatchObject({ ok: false, reason: 'key_not_found' })
      expect(http.calls).toHaveLength(0)
    })
  })

  describe('media type', () => {
    it('accepts application/json by default, since static hosts send it', async () => {
      const http = recorder(() =>
        jwksResponse([key.publicJwk], { 'content-type': 'application/json' }),
      )
      const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
      expect(await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })).toMatchObject({
        ok: true,
      })
    })

    it('rejects it in strict mode', async () => {
      const http = recorder(() =>
        jwksResponse([key.publicJwk], { 'content-type': 'application/json' }),
      )
      const resolver = createDirectoryResolver({
        http,
        clock: fixedClock(NOW),
        mediaType: 'strict',
      })
      expect(await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })).toMatchObject({
        reason: 'directory_malformed',
      })
    })

    it('rejects an outright wrong media type in either mode', async () => {
      const http = recorder(() => jwksResponse([key.publicJwk], { 'content-type': 'text/html' }))
      const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
      expect(await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })).toMatchObject({
        reason: 'directory_malformed',
      })
    })

    it('tolerates parameters on the media type', async () => {
      const http = recorder(() =>
        jwksResponse([key.publicJwk], {
          'content-type': 'application/http-message-signatures-directory+json; charset=utf-8',
        }),
      )
      const resolver = createDirectoryResolver({ http, clock: fixedClock(NOW) })
      expect(await resolver.resolve({ origin: ORIGIN, keyid: key.keyid, now: NOW })).toMatchObject({
        ok: true,
      })
    })
  })
})
