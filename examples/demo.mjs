#!/usr/bin/env node
/**
 * A complete Badge deployment in one file: an agent that signs, a key
 * directory, a site that verifies, and a policy that decides.
 *
 * Run with: pnpm run build && node examples/demo.mjs
 *
 * Nothing here is stubbed. It is a real Ed25519 key, a real JWKS served over
 * HTTP, real RFC 9421 signatures, and the real verifier — so if this prints
 * `verified`, the whole path works.
 */
import { createServer, request as httpRequest } from 'node:http'
import { badgeNodeMiddleware } from '../packages/adapters/dist/index.js'
import { buildDirectory, createDirectoryResolver } from '../packages/directory/dist/index.js'
import { createBadge, jsonSink } from '../packages/middleware/dist/index.js'
import { generateSigningKey, signRequest } from '../packages/testkit/dist/index.js'

// ---------------------------------------------------------------- the agent
// An agent generates a key and publishes the public half at the well-known
// path. Its Signature-Agent header names that origin.
//
// The origin must be https: Badge refuses anything else, because a key
// directory fetched over plain HTTP can be rewritten in flight by anyone on the
// path, which would let them substitute their own key. So this demo names a
// real https origin and serves its directory in-process, below.
const key = await generateSigningKey()
const directoryDoc = await buildDirectory({ keys: [key.publicJwk] })
const agentOrigin = 'https://agent.example'

// ----------------------------------------------------------------- the site
// Note the first two rules. A forged signature is hostile; Badge's own
// inability to check is not. That distinction is the point of the class axis.
const policy = {
  version: 1,
  default: 'log-only',
  rules: [
    { id: 'forgeries-are-hostile', action: 'deny', when: { class: 'untrusted' } },
    { id: 'our-outage-is-not-their-fault', action: 'log-only', when: { class: 'unverifiable' } },
    {
      id: 'docs-open-to-agents',
      action: 'allow',
      when: { status: 'verified' },
      routes: ['GET /docs/**'],
    },
    {
      id: 'no-agents-at-checkout',
      action: 'deny',
      when: { class: ['ok', 'untrusted', 'malformed', 'expired'] },
      routes: ['POST /checkout/**'],
    },
  ],
}

/**
 * agent.example is not a real host, so the demo serves its directory in-process.
 *
 * `HttpClient` is the documented extension point for exactly this. A production
 * deployment passes nothing here and gets `nodeHttpClient()`, which fetches over
 * https with the SSRF guard, the redirect refusal and the size cap. Everything
 * above this line — caching, thumbprint matching, JWKS parsing, the verifier —
 * is the shipped code path.
 */
const directoryUrl = `${agentOrigin}${directoryDoc.path}`
const demoHttpClient = {
  async get(url) {
    if (url !== directoryUrl) return { status: 404, headers: new Map(), body: new Uint8Array() }
    console.log(`   fetch ${url}`)
    return {
      status: 200,
      headers: new Map(Object.entries(directoryDoc.headers)),
      body: new TextEncoder().encode(directoryDoc.body),
    }
  },
}

const badge = createBadge({
  policy,
  keys: createDirectoryResolver({ http: demoHttpClient }),
  sinks: [jsonSink({ write: (line) => console.log(`   log  ${line}`) })],
})

const siteServer = createServer((req, res) => {
  badgeNodeMiddleware(badge, { debugHeaders: true })(req, res, () => {
    res.writeHead(200).end('the application handled this request\n')
  })
})
await listen(siteServer)
const sitePort = siteServer.address().port
const siteAuthority = `127.0.0.1:${sitePort}`

// ------------------------------------------------------------------ the run
const sign = async (overrides) =>
  (
    await signRequest({
      key,
      scheme: 'http',
      authority: siteAuthority,
      signatureAgent: agentOrigin,
      ...overrides,
    })
  ).headers

const scenarios = [
  ['an ordinary browser, no signature', {}, 'GET', '/docs/intro'],
  ['a verified agent reading the docs', await sign({ path: '/docs/intro' }), 'GET', '/docs/intro'],
  [
    'a forged signature',
    await sign({ path: '/docs/intro', tamperSignature: true }),
    'GET',
    '/docs/intro',
  ],
  [
    'an expired signature',
    await sign({ path: '/docs/intro', created: 1_700_000_000, expires: 1_700_000_060 }),
    'GET',
    '/docs/intro',
  ],
  [
    'a verified agent at checkout',
    await sign({ method: 'POST', path: '/checkout/pay' }),
    'POST',
    '/checkout/pay',
  ],
]

for (const [label, headers, method, path] of scenarios) {
  console.log(`\n${label}`)
  const reply = await send(headers, method, path)
  console.log(
    `   ->   ${reply.status}  ${reply.headers['x-badge-status']}/${reply.headers['x-badge-reason']}` +
      `  rule=${reply.headers['x-badge-rule']}`,
  )
}

console.log('')
siteServer.close()

// ----------------------------------------------------------------- plumbing
function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
}

function send(headers, method, path) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port: sitePort, method, path, headers }, (res) => {
      let body = ''
      res.on('data', (c) => (body += c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }))
    })
    req.on('error', reject)
    req.end()
  })
}
