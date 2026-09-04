import { generateSigningKey, signRequest, type SigningKey } from '@badge/testkit'
import { beforeAll, describe, expect, it } from 'vitest'
import { staticKeyResolver, type KeyRequest, type KeyResolver } from './keys.js'
import { createRequest } from './request.js'
import { createVerifier } from './verifier.js'

/**
 * Guards for ARCHITECTURE.md §17.
 *
 * The structural assertions are the real guard: they are deterministic and they
 * catch the regression that actually matters, which is machinery creeping onto
 * the path that unsigned traffic takes. The timing ceiling is deliberately loose
 * — the §17 target is under 10µs, but a CI runner under load is not a
 * measurement device, and a flaky performance test gets deleted rather than
 * fixed. It is set to catch a hundredfold regression, not a tenth of one.
 */

const NOW = 1_735_689_600
let key: SigningKey

beforeAll(async () => {
  key = await generateSigningKey()
})

const spyResolver = (): KeyResolver & { calls: KeyRequest[] } => {
  const calls: KeyRequest[] = []
  return {
    calls,
    async resolve(request) {
      calls.push(request)
      return { ok: false, reason: 'key_not_found' }
    },
  }
}

const unsigned = () =>
  createRequest({
    method: 'GET',
    scheme: 'https',
    authority: 'example.com',
    path: '/docs/intro',
    query: 'a=1',
    headers: { 'user-agent': 'Mozilla/5.0', accept: 'text/html', cookie: 'session=abc' },
  })

describe('the unsigned path', () => {
  it('resolves no keys', async () => {
    const keys = spyResolver()
    await createVerifier({ keys, clock: { now: () => NOW } }).verify(unsigned())
    expect(keys.calls).toHaveLength(0)
  })

  it('reads only the two fields the presence test needs', async () => {
    const read: string[] = []
    const request = unsigned()
    const spied = {
      ...request,
      header: (name: string) => {
        read.push(name.toLowerCase())
        return request.header(name)
      },
    }
    await createVerifier({
      keys: staticKeyResolver({}),
      clock: { now: () => NOW },
    }).verify(spied)
    expect(new Set(read)).toEqual(new Set(['signature-input', 'signature-agent']))
  })

  it('reports the verdict without timing out of band', async () => {
    const verdict = await createVerifier({
      keys: staticKeyResolver({}),
      clock: { now: () => NOW },
    }).verify(unsigned())
    expect(verdict.reason).toBe('no_signature_fields')
    expect('directoryUs' in verdict.timing).toBe(false)
    expect('cache' in verdict.timing).toBe(false)
  })

  it('stays far cheaper than the signed path', async () => {
    const verifier = createVerifier({
      keys: staticKeyResolver({ 'https://agent.example': [key.publicJwk] }),
      clock: { now: () => NOW },
    })
    const signed = (await signRequest({ key, created: NOW, expires: NOW + 60 })).request

    const median = async (run: () => Promise<unknown>): Promise<number> => {
      for (let i = 0; i < 50; i += 1) await run()
      const samples: number[] = []
      for (let i = 0; i < 200; i += 1) {
        const started = performance.now()
        await run()
        samples.push(performance.now() - started)
      }
      samples.sort((a, b) => a - b)
      return samples[Math.floor(samples.length / 2)] as number
    }

    const unsignedMs = await median(async () => verifier.verify(unsigned()))
    const signedMs = await median(async () => verifier.verify(signed))

    // §17 targets under 10µs. This ceiling is 20x that, chosen so a loaded CI
    // runner cannot fail the build while a real regression still would.
    expect(unsignedMs).toBeLessThan(0.2)
    expect(unsignedMs).toBeLessThan(signedMs)
  })
})
