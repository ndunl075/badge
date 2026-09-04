#!/usr/bin/env node
/**
 * Regenerate spec-vectors/verdicts.json.
 *
 * Signed vectors cannot be written by hand, so they are generated once and
 * committed. Ed25519 is deterministic and the key is fixed (RFC 8037 Appendix
 * A.1), so regenerating produces byte-identical output unless behaviour
 * actually changed — which makes a diff here meaningful rather than noise.
 *
 * Run: pnpm run build && node scripts/generate-vectors.mjs
 */
import { writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { jwkThumbprint } from '../packages/core/dist/index.js'
import { signRequest } from '../packages/testkit/dist/index.js'

const NOW = 1735689600

// RFC 8037 Appendix A.1.
const PRIVATE_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  d: 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
  x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
}
const PUBLIC_JWK = { kty: 'OKP', crv: 'Ed25519', x: PRIVATE_JWK.x }

const privateKey = await crypto.subtle.importKey('jwk', PRIVATE_JWK, { name: 'Ed25519' }, false, [
  'sign',
])
const key = { privateKey, publicJwk: PUBLIC_JWK, keyid: await jwkThumbprint(PUBLIC_JWK) }

const OTHER_PUBLIC_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AILyhc',
}

const base = { authority: 'example.com', path: '/docs/intro', created: NOW, expires: NOW + 60 }

const signed = async (overrides) => {
  const result = await signRequest({ key, ...base, ...overrides })
  return {
    method: 'GET',
    scheme: 'https',
    authority: overrides.authority ?? base.authority,
    path: overrides.path ?? base.path,
    query: overrides.query ?? '',
    headers: result.headers,
  }
}

const cases = [
  ['a valid web-bot-auth signature', await signed({}), 'verified', 'ok', 'ok'],
  [
    'a tampered signature',
    await signed({ tamperSignature: true }),
    'claimed',
    'untrusted',
    'signature_invalid',
  ],
  [
    'an expired signature',
    await signed({ created: NOW - 600, expires: NOW - 300 }),
    'claimed',
    'expired',
    'signature_expired',
  ],
  [
    'a signature created in the future',
    await signed({ created: NOW + 600, expires: NOW + 660 }),
    'claimed',
    'expired',
    'created_in_future',
  ],
  [
    'a validity window beyond the profile ceiling',
    await signed({ expires: NOW + 90000 }),
    'claimed',
    'malformed',
    'validity_window_too_long',
  ],
  [
    'a signature tagged for something else',
    await signed({ tag: 'not-web-bot-auth' }),
    'unknown',
    'absent',
    'no_web_bot_auth_tag',
  ],
  ['no keyid', await signed({ keyid: null }), 'claimed', 'malformed', 'missing_keyid'],
  [
    'an unsupported algorithm',
    await signed({ alg: 'rsa-pss-sha512' }),
    'claimed',
    'malformed',
    'unsupported_algorithm',
  ],
  [
    'no Signature-Agent',
    await signed({ signatureAgent: null }),
    'claimed',
    'malformed',
    'signature_agent_missing',
  ],
  [
    'Signature-Agent present but not covered',
    await signed({ components: ['"@authority"'] }),
    'claimed',
    'malformed',
    'covered_components_insufficient',
  ],
  [
    '@authority not covered',
    await signed({ components: ['"signature-agent"'] }),
    'claimed',
    'malformed',
    'covered_components_insufficient',
  ],
  [
    'a request carrying no Web Bot Auth fields',
    {
      method: 'GET',
      scheme: 'https',
      authority: 'example.com',
      path: '/docs/intro',
      query: '',
      headers: {},
    },
    'unknown',
    'absent',
    'no_signature_fields',
  ],
]

const document = {
  description:
    'End-to-end verifier vectors. The signing key is RFC 8037 Appendix A.1 and Ed25519 is ' +
    'deterministic, so these bytes are stable. Replay each request against a verifier holding ' +
    'the published key and expect the given verdict. Regenerate with scripts/generate-vectors.mjs.',
  profile: 'wba-2026-03',
  now: NOW,
  signatureAgentOrigin: 'https://agent.example',
  publishedKeys: [PUBLIC_JWK],
  unrelatedKey: OTHER_PUBLIC_JWK,
  vectors: cases.map(([name, request, status, klass, reason]) => ({
    name,
    request,
    expect: { status, class: klass, reason },
  })),
}

const out = fileURLToPath(new URL('../spec-vectors/verdicts.json', import.meta.url))
await writeFile(out, `${JSON.stringify(document, null, 2)}\n`)
console.log(`wrote ${document.vectors.length} vectors to ${out}`)
