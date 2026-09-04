import { createServer, type Server } from 'node:http'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { HttpClientError, nodeHttpClient, requestWithLimits } from './http.js'

/**
 * The transport limits are exercised against a real server over plain HTTP.
 * `nodeHttpClient` refuses anything but https, so its own scheme and address
 * guards are tested separately, below.
 */
let server: Server
let base: string

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost')
    switch (url.pathname) {
      case '/ok':
        res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'max-age=60' })
        res.end('{"keys":[]}')
        return
      case '/big':
        res.writeHead(200)
        res.end('x'.repeat(4096))
        return
      case '/declares-big':
        res.writeHead(200, { 'content-length': '999999' })
        res.end('x'.repeat(10))
        return
      case '/slow':
        setTimeout(() => {
          res.writeHead(200)
          res.end('late')
        }, 2000).unref()
        return
      case '/redirect':
        res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' })
        res.end()
        return
      default:
        res.writeHead(404)
        res.end('nope')
    }
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('no address')
  base = `http://127.0.0.1:${address.port}`
})

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()))
})

const fetchLocal = (path: string, overrides = {}) =>
  requestWithLimits(
    `${base}${path}`,
    { timeoutMs: 1000, maxBytes: 2048, ...overrides },
    { allowPrivateAddresses: true },
  )

describe('requestWithLimits', () => {
  it('returns status, headers and body', async () => {
    const response = await fetchLocal('/ok')
    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toBe('application/json')
    expect(response.headers.get('cache-control')).toBe('max-age=60')
    expect(new TextDecoder().decode(response.body)).toBe('{"keys":[]}')
  })

  it('surfaces a non-200 rather than throwing', async () => {
    expect((await fetchLocal('/missing')).status).toBe(404)
  })

  it('aborts a body over the cap', async () => {
    await expect(fetchLocal('/big', { maxBytes: 100 })).rejects.toMatchObject({
      kind: 'too-large',
    })
  })

  // Cheaper still: refuse before reading a single byte of body.
  it('refuses a declared Content-Length over the cap', async () => {
    await expect(fetchLocal('/declares-big', { maxBytes: 100 })).rejects.toMatchObject({
      kind: 'too-large',
    })
  })

  it('gives up at the timeout', async () => {
    await expect(fetchLocal('/slow', { timeoutMs: 100 })).rejects.toMatchObject({
      kind: 'timeout',
    })
  })

  // A redirect is the obvious way around an origin check. We return the 3xx
  // and never follow it.
  it('does not follow redirects', async () => {
    const response = await fetchLocal('/redirect')
    expect(response.status).toBe(302)
    expect(response.headers.get('location')).toBe('http://169.254.169.254/latest/meta-data/')
  })

  it('reports a refused connection as a network failure', async () => {
    await expect(
      requestWithLimits(
        'http://127.0.0.1:1/x',
        { timeoutMs: 500, maxBytes: 100 },
        { allowPrivateAddresses: true },
      ),
    ).rejects.toMatchObject({ kind: 'network' })
  })
})

describe('nodeHttpClient guards', () => {
  const client = nodeHttpClient()
  const options = { timeoutMs: 500, maxBytes: 1024 }

  it.each(['http://agent.example/.well-known/x', 'ftp://agent.example/x', 'file:///etc/passwd'])(
    'refuses the non-https URL %s',
    async (url) => {
      await expect(client.get(url, options)).rejects.toMatchObject({ kind: 'blocked' })
    },
  )

  it('refuses a malformed URL', async () => {
    await expect(client.get('not a url', options)).rejects.toBeInstanceOf(HttpClientError)
  })

  // The guard that matters: the connection is never established because the
  // pinned lookup refuses to hand back a loopback address.
  it('refuses a host that resolves to loopback', async () => {
    await expect(client.get('https://localhost/x', options)).rejects.toMatchObject({
      kind: 'blocked',
    })
  })

  // Node's socket layer connects straight to an IP literal without ever
  // consulting the custom lookup, so literals need their own check. This test
  // caught that hole.
  it('refuses a literal private address', async () => {
    await expect(client.get('https://127.0.0.1/x', options)).rejects.toMatchObject({
      kind: 'blocked',
    })
  })

  it('refuses the cloud metadata endpoint by literal address', async () => {
    await expect(
      client.get('https://169.254.169.254/latest/meta-data/', options),
    ).rejects.toMatchObject({ kind: 'blocked' })
  })

  it('refuses a bracketed IPv6 loopback literal', async () => {
    await expect(client.get('https://[::1]/x', options)).rejects.toMatchObject({ kind: 'blocked' })
  })

  it('opts in to private addresses only when explicitly configured', async () => {
    const permissive = nodeHttpClient({ allowPrivateAddresses: true })
    // Connection is attempted (and refused by the OS), proving the address
    // guard no longer short-circuits it.
    await expect(permissive.get('https://127.0.0.1:1/x', options)).rejects.toMatchObject({
      kind: 'network',
    })
  })
})
