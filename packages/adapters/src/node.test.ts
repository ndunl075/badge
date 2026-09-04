import { createServer, request as httpRequest, type IncomingMessage, type Server } from 'node:http'
import { staticKeyResolver } from '@badge/core'
import { createBadge } from '@badge/middleware'
import type { Policy } from '@badge/policy'
import { fixedClock, generateSigningKey, signRequest, type SigningKey } from '@badge/testkit'
import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import { badgeNodeMiddleware, fromNodeRequest, type NodeAdapterOptions } from './node.js'

const NOW = 1_735_689_600
const ORIGIN = 'https://agent.example'

let key: SigningKey
let server: Server | undefined

beforeAll(async () => {
  key = await generateSigningKey()
})

afterEach(async () => {
  if (server !== undefined) {
    const closing = server
    server = undefined
    await new Promise<void>((resolve) => closing.close(() => resolve()))
  }
})

const allowVerified: Policy = {
  version: 1,
  default: 'log-only',
  rules: [{ id: 'allow-verified', action: 'allow', when: { status: 'verified' } }],
}

const denyVerified: Policy = {
  version: 1,
  default: 'log-only',
  rules: [{ id: 'no-agents', action: 'deny', when: { status: 'verified' } }],
}

const start = async (policy: Policy, options: NodeAdapterOptions = {}): Promise<number> => {
  const badge = createBadge({
    policy,
    keys: staticKeyResolver({ [ORIGIN]: [key.publicJwk] }),
    clock: fixedClock(NOW),
    sinks: [],
  })
  const middleware = badgeNodeMiddleware(badge, options)
  server = createServer((req, res) => {
    middleware(req, res, (err) => {
      if (err !== undefined) {
        res.statusCode = 500
        res.end('middleware error')
        return
      }
      res.statusCode = 200
      res.end('handler reached')
    })
  })
  await new Promise<void>((resolve) => server?.listen(0, '127.0.0.1', resolve))
  const address = server?.address()
  if (address === null || address === undefined || typeof address === 'string') {
    throw new Error('no address')
  }
  return address.port
}

interface Reply {
  status: number
  headers: NodeJS.Dict<string | string[]>
  body: string
}

const send = async (port: number, headers: Record<string, string>, path = '/'): Promise<Reply> =>
  await new Promise<Reply>((resolve, reject) => {
    const req = httpRequest(
      { host: '127.0.0.1', port, path, method: 'GET', headers },
      (res: IncomingMessage) => {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (chunk: string) => (body += chunk))
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }))
      },
    )
    req.on('error', reject)
    req.end()
  })

const signFor = async (port: number, overrides = {}) =>
  await signRequest({
    key,
    created: NOW,
    expires: NOW + 60,
    scheme: 'http',
    authority: `127.0.0.1:${port}`,
    ...overrides,
  })

describe('badgeNodeMiddleware', () => {
  it('lets an unsigned request through under the default policy', async () => {
    const port = await start(allowVerified)
    expect((await send(port, {})).status).toBe(200)
  })

  it('verifies a real signed request end to end', async () => {
    const port = await start(allowVerified)
    const signed = await signFor(port)
    const reply = await send(port, signed.headers)
    expect(reply.status).toBe(200)
    expect(reply.body).toBe('handler reached')
  })

  it('denies with 403 and marks the response uncacheable', async () => {
    const port = await start(denyVerified)
    const signed = await signFor(port)
    const reply = await send(port, signed.headers)
    expect(reply.status).toBe(403)
    // A denial is specific to this caller's credentials and must never be
    // stored by a shared cache in front of the origin.
    expect(reply.headers['cache-control']).toBe('no-store')
    expect(reply.body).toBe('Forbidden')
  })

  it('uses a configured deny status and body', async () => {
    const port = await start(denyVerified, { denyStatus: 401, denyBody: 'nope' })
    const reply = await send(port, (await signFor(port)).headers)
    expect(reply.status).toBe(401)
    expect(reply.body).toBe('nope')
  })

  // In production these are a policy oracle: probe until you learn which rule
  // fires and why.
  it('adds no X-Badge headers by default', async () => {
    const port = await start(allowVerified)
    const reply = await send(port, (await signFor(port)).headers)
    expect(reply.headers['x-badge-status']).toBeUndefined()
    expect(reply.headers['x-badge-reason']).toBeUndefined()
  })

  it('adds them in debug mode', async () => {
    const port = await start(allowVerified, { debugHeaders: true })
    const reply = await send(port, (await signFor(port)).headers)
    expect(reply.headers['x-badge-status']).toBe('verified')
    expect(reply.headers['x-badge-reason']).toBe('ok')
    expect(reply.headers['x-badge-rule']).toBe('allow-verified')
  })

  it('reports the decision to a callback', async () => {
    const seen: string[] = []
    const port = await start(allowVerified, {
      onDecision: (decision) => seen.push(`${decision.verdict.reason}/${decision.ruleId}`),
    })
    await send(port, (await signFor(port)).headers)
    expect(seen).toEqual(['ok/allow-verified'])
  })

  // The failure the architecture keeps warning about: a proxy rewrites Host and
  // the verdict looks cryptographic.
  describe('authority behind a proxy', () => {
    it('fails when the proxy rewrote Host and Badge trusts it', async () => {
      const port = await start(allowVerified, { debugHeaders: true })
      const signed = await signFor(port, { authority: 'public.example' })
      const reply = await send(port, signed.headers)
      expect(reply.headers['x-badge-reason']).toBe('signature_invalid')
    })

    it('succeeds when told to trust the forwarded host', async () => {
      const port = await start(allowVerified, {
        authority: 'forwarded',
        scheme: 'forwarded',
        debugHeaders: true,
      })
      const signed = await signRequest({
        key,
        created: NOW,
        expires: NOW + 60,
        scheme: 'https',
        authority: 'public.example',
      })
      const reply = await send(port, {
        ...signed.headers,
        'x-forwarded-host': 'public.example',
        'x-forwarded-proto': 'https',
      })
      expect(reply.headers['x-badge-reason']).toBe('ok')
      expect(reply.status).toBe(200)
    })

    it('succeeds with a fixed authority', async () => {
      const port = await start(allowVerified, {
        authority: { fixed: 'public.example' },
        scheme: 'https',
        debugHeaders: true,
      })
      const signed = await signRequest({
        key,
        created: NOW,
        expires: NOW + 60,
        scheme: 'https',
        authority: 'public.example',
      })
      expect((await send(port, signed.headers)).headers['x-badge-reason']).toBe('ok')
    })
  })
})

describe('fromNodeRequest', () => {
  const fake = (rawHeaders: string[], url = '/a/b?x=1'): IncomingMessage =>
    ({
      method: 'get',
      url,
      rawHeaders,
      socket: {},
      headers: {},
    }) as unknown as IncomingMessage

  it('splits the target into path and query', () => {
    const request = fromNodeRequest(fake(['Host', 'example.com']))
    expect(request.path).toBe('/a/b')
    expect(request.query).toBe('x=1')
  })

  it('handles a target with no query', () => {
    const request = fromNodeRequest(fake(['Host', 'example.com'], '/a'))
    expect(request.query).toBe('')
  })

  // Node discards duplicates of some field names when building `headers`, and a
  // covered field sent twice must reach the base exactly as it arrived.
  it('preserves duplicate fields from rawHeaders in order', () => {
    const request = fromNodeRequest(
      fake(['Host', 'example.com', 'X-Thing', 'one', 'x-thing', 'two']),
    )
    expect(request.header('x-thing')).toBe('one, two')
  })

  it('is case-insensitive about field names', () => {
    const request = fromNodeRequest(fake(['Host', 'example.com', 'Signature-Agent', '"https://a"']))
    expect(request.header('signature-agent')).toBe('"https://a"')
  })

  it('reads the RFC 7239 Forwarded header when configured', () => {
    const request = fromNodeRequest(
      fake(['Host', 'internal', 'Forwarded', 'for=1.2.3.4;host="public.example";proto=https']),
      { authority: 'forwarded', scheme: 'forwarded' },
    )
    expect(request.authority).toBe('public.example')
    expect(request.scheme).toBe('https')
  })

  it('takes the first element of a multi-hop Forwarded header', () => {
    const request = fromNodeRequest(
      fake(['Host', 'internal', 'Forwarded', 'host=first.example, host=second.example']),
      { authority: 'forwarded' },
    )
    expect(request.authority).toBe('first.example')
  })

  it('ignores forwarding headers unless configured to trust them', () => {
    const request = fromNodeRequest(
      fake(['Host', 'real.example', 'X-Forwarded-Host', 'attacker.example']),
    )
    expect(request.authority).toBe('real.example')
  })
})
