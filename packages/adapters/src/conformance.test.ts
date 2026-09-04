import type { IncomingMessage, ServerResponse } from 'node:http'
import { staticKeyResolver } from '@badge/core'
import { createBadge, type Badge } from '@badge/middleware'
import type { Policy } from '@badge/policy'
import { fixedClock, generateSigningKey, signRequest, type SigningKey } from '@badge/testkit'
import { beforeAll, describe, expect, it } from 'vitest'
import { badgeFastify, type FastifyLikeReply } from './fastify.js'
import { badgeFetchMiddleware } from './fetch.js'
import { badgeNodeMiddleware } from './node.js'

/**
 * One suite, every adapter (ARCHITECTURE.md §16).
 *
 * Adapters are supposed to be thin: build a request, call inspect, apply the
 * result. The way to keep them thin is to assert that they all reach the same
 * decision for the same request. A divergence here means verification logic has
 * leaked into an adapter.
 */

const NOW = 1_735_689_600
const ORIGIN = 'https://agent.example'
const AUTHORITY = 'example.com'

let key: SigningKey

beforeAll(async () => {
  key = await generateSigningKey()
})

const policy: Policy = {
  version: 1,
  default: 'log-only',
  rules: [
    { id: 'deny-forgeries', action: 'deny', when: { class: 'untrusted' } },
    { id: 'allow-verified', action: 'allow', when: { status: 'verified' } },
  ],
}

const makeBadge = (): Badge =>
  createBadge({
    policy,
    keys: staticKeyResolver({ [ORIGIN]: [key.publicJwk] }),
    clock: fixedClock(NOW),
    sinks: [],
  })

interface Observed {
  readonly reason: string
  readonly rule: string
  readonly action: string
  readonly status: number
  readonly handlerReached: boolean
}

/** Drive the Node/Connect adapter without a socket. */
const viaNode = async (headers: Record<string, string>, path: string): Promise<Observed> => {
  const observed = { reason: '', rule: '', action: '' }
  const middleware = badgeNodeMiddleware(makeBadge(), {
    onDecision: (decision) => {
      observed.reason = decision.verdict.reason
      observed.rule = decision.ruleId
      observed.action = decision.action
    },
  })

  const rawHeaders = Object.entries({ host: AUTHORITY, ...headers }).flatMap(([k, v]) => [k, v])
  const req = { method: 'GET', url: path, rawHeaders, socket: {} } as unknown as IncomingMessage

  let status = 200
  let handlerReached = false

  // Settle on whichever the middleware does: call next, or end the response.
  // Timing out on a tick would race the async verification instead.
  await new Promise<void>((resolve) => {
    const res = {
      set statusCode(value: number) {
        status = value
      },
      get statusCode() {
        return status
      },
      setHeader: () => undefined,
      end: () => resolve(),
    } as unknown as ServerResponse

    middleware(req, res, () => {
      handlerReached = true
      resolve()
    })
  })
  return { ...observed, status, handlerReached }
}

const viaFetch = async (headers: Record<string, string>, path: string): Promise<Observed> => {
  const observed = { reason: '', rule: '', action: '' }
  const middleware = badgeFetchMiddleware(makeBadge(), {
    onDecision: (decision) => {
      observed.reason = decision.verdict.reason
      observed.rule = decision.ruleId
      observed.action = decision.action
    },
  })
  let handlerReached = false
  const response = await middleware(
    new Request(`https://${AUTHORITY}${path}`, { headers }),
    async () => {
      handlerReached = true
      return new Response('handler reached')
    },
  )
  return { ...observed, status: response.status, handlerReached }
}

const viaFastify = async (headers: Record<string, string>, path: string): Promise<Observed> => {
  const observed = { reason: '', rule: '', action: '' }
  const hook = badgeFastify(makeBadge(), {
    onDecision: (decision) => {
      observed.reason = decision.verdict.reason
      observed.rule = decision.ruleId
      observed.action = decision.action
    },
  })
  const rawHeaders = Object.entries({ host: AUTHORITY, ...headers }).flatMap(([k, v]) => [k, v])
  const raw = { method: 'GET', url: path, rawHeaders, socket: {} } as unknown as IncomingMessage

  let status = 200
  let sent = false
  const reply: FastifyLikeReply = {
    code(value) {
      status = value
      return reply
    },
    header() {
      return reply
    },
    send() {
      sent = true
      return undefined
    },
  }
  await hook({ raw }, reply)
  return { ...observed, status, handlerReached: !sent }
}

const adapters = [
  ['node', viaNode],
  ['fetch', viaFetch],
  ['fastify', viaFastify],
] as const

const cases = [
  {
    name: 'a valid signature',
    headers: async () =>
      (await signRequest({ key, created: NOW, expires: NOW + 60, authority: AUTHORITY })).headers,
    reason: 'ok',
    rule: 'allow-verified',
    action: 'allow',
    status: 200,
  },
  {
    name: 'a forged signature',
    headers: async () =>
      (
        await signRequest({
          key,
          created: NOW,
          expires: NOW + 60,
          authority: AUTHORITY,
          tamperSignature: true,
        })
      ).headers,
    reason: 'signature_invalid',
    rule: 'deny-forgeries',
    action: 'deny',
    status: 403,
  },
  {
    name: 'an expired signature',
    headers: async () =>
      (await signRequest({ key, created: NOW - 600, expires: NOW - 300, authority: AUTHORITY }))
        .headers,
    reason: 'signature_expired',
    rule: 'default',
    action: 'log-only',
    status: 200,
  },
  {
    name: 'no signature at all',
    headers: async () => ({}),
    reason: 'no_signature_fields',
    rule: 'default',
    action: 'log-only',
    status: 200,
  },
] as const

describe('adapter conformance', () => {
  for (const expected of cases) {
    it(`reaches the same decision for ${expected.name} in every adapter`, async () => {
      const headers = await expected.headers()
      const results = await Promise.all(
        adapters.map(async ([name, run]) => [name, await run(headers, '/docs/intro')] as const),
      )
      for (const [name, observed] of results) {
        expect({ adapter: name, ...observed }).toEqual({
          adapter: name,
          reason: expected.reason,
          rule: expected.rule,
          action: expected.action,
          status: expected.status,
          handlerReached: expected.action !== 'deny',
        })
      }
    })
  }

  it('agrees on the covered authority across adapters', async () => {
    const signed = await signRequest({
      key,
      created: NOW,
      expires: NOW + 60,
      authority: 'wrong.example',
    })
    for (const [, run] of adapters) {
      expect((await run(signed.headers, '/docs/intro')).reason).toBe('signature_invalid')
    }
  })
})
