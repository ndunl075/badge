import {
  fixedClock,
  generateSigningKey,
  signRequest,
  type SignRequestOptions,
  type SigningKey,
} from '@badge/testkit'
import { beforeAll, describe, expect, it } from 'vitest'
import type { Jwk } from './crypto.js'
import { staticKeyResolver, type KeyResolution, type KeyResolver, type NonceStore } from './keys.js'
import { memoryNonceStore } from './nonce.js'
import { createRequest } from './request.js'
import type { ReasonCode } from './reasons.js'
import { createVerifier, type VerifierOptions } from './verifier.js'
import type { NormalizedRequest } from './types.js'

const NOW = 1_735_689_600
const ORIGIN = 'https://agent.example'

let key: SigningKey

beforeAll(async () => {
  key = await generateSigningKey()
})

const verifierWith = (
  overrides: Partial<VerifierOptions> = {},
  keys: Readonly<Record<string, readonly Jwk[]>> = { [ORIGIN]: [] },
) =>
  createVerifier({
    keys: staticKeyResolver(keys),
    clock: fixedClock(NOW),
    ...overrides,
  })

const defaultVerifier = () => verifierWith({}, { [ORIGIN]: [key.publicJwk] })

/** Sign with sane defaults anchored to the test clock. */
const sign = async (options: Omit<SignRequestOptions, 'key'> = {}) =>
  signRequest({ key, created: NOW, expires: NOW + 60, ...options })

describe('verify', () => {
  it('verifies a well-formed signed request', async () => {
    const signed = await sign()
    const verdict = await defaultVerifier().verify(signed.request)
    expect(verdict).toMatchObject({
      status: 'verified',
      class: 'ok',
      reason: 'ok',
      signatureAgent: ORIGIN,
      keyid: key.keyid,
      label: 'sig1',
      created: NOW,
      expires: NOW + 60,
      covered: ['@authority', 'signature-agent'],
    })
  })

  it('records the profile that judged the request', async () => {
    const verdict = await defaultVerifier().verify((await sign()).request)
    expect(verdict.profile).toBe('wba-2026-03')
  })

  it('records timing and the cache tier that answered', async () => {
    const verdict = await defaultVerifier().verify((await sign()).request)
    expect(verdict.timing.totalUs).toBeGreaterThanOrEqual(0)
    expect(verdict.timing.directoryUs).toBeGreaterThanOrEqual(0)
    expect(verdict.timing.cache).toBe('hit')
  })

  it('picks the web-bot-auth signature and ignores other signatures on the message', async () => {
    const signed = await sign()
    const input = signed.request.header('signature-input') as string
    const signature = signed.request.header('signature') as string
    const request = createRequest({
      method: 'GET',
      scheme: 'https',
      authority: 'example.com',
      path: '/',
      headers: {
        'signature-agent': signed.request.header('signature-agent') as string,
        'signature-input': `other=("@method");tag="something-else", ${input}`,
        signature: `other=:AAAA:, ${signature}`,
      },
    })
    expect((await defaultVerifier().verify(request)).reason).toBe('ok')
  })
})

/**
 * Negative-path parity (ARCHITECTURE.md §16): every reason code the verifier can
 * produce has a test that produces it. A reason code with no test is a lie in
 * the documentation.
 */
describe('failure paths', () => {
  const expectReason = async (
    request: NormalizedRequest,
    reason: ReasonCode,
    verifier = defaultVerifier(),
  ) => {
    const verdict = await verifier.verify(request)
    expect(verdict.reason).toBe(reason)
    return verdict
  }

  const plain = (headers: Record<string, string>): NormalizedRequest =>
    createRequest({ method: 'GET', scheme: 'https', authority: 'example.com', path: '/', headers })

  it('unknown / no_signature_fields when nothing is claimed', async () => {
    const verdict = await expectReason(plain({}), 'no_signature_fields')
    expect(verdict.status).toBe('unknown')
    expect(verdict.class).toBe('absent')
  })

  it('signature_input_malformed when an agent is named but nothing is signed', async () => {
    await expectReason(plain({ 'signature-agent': `"${ORIGIN}"` }), 'signature_input_malformed')
  })

  it('signature_input_malformed on unparseable Signature-Input', async () => {
    await expectReason(
      plain({ 'signature-input': 'not a dictionary!' }),
      'signature_input_malformed',
    )
  })

  it('signature_malformed when Signature is absent', async () => {
    const signed = await sign()
    await expectReason(
      plain({
        'signature-agent': signed.request.header('signature-agent') as string,
        'signature-input': signed.request.header('signature-input') as string,
      }),
      'signature_malformed',
    )
  })

  it('signature_malformed when Signature is unparseable', async () => {
    const signed = await sign()
    await expectReason(
      plain({
        'signature-agent': signed.request.header('signature-agent') as string,
        'signature-input': signed.request.header('signature-input') as string,
        signature: 'nonsense!!',
      }),
      'signature_malformed',
    )
  })

  it('signature_malformed when the labels do not line up', async () => {
    const signed = await sign()
    await expectReason(
      plain({
        'signature-agent': signed.request.header('signature-agent') as string,
        'signature-input': signed.request.header('signature-input') as string,
        signature: (signed.request.header('signature') as string).replace('sig1=', 'other='),
      }),
      'signature_malformed',
    )
  })

  it('no_web_bot_auth_tag when the signature is tagged for something else', async () => {
    const signed = await sign({ tag: 'not-web-bot-auth' })
    const verdict = await expectReason(signed.request, 'no_web_bot_auth_tag')
    expect(verdict.status).toBe('unknown')
  })

  // A Token spelling web-bot-auth is a different RFC 9651 value than the String.
  it('no_web_bot_auth_tag when the tag is a token rather than a string', async () => {
    const signed = await sign()
    const input = (signed.request.header('signature-input') as string).replace(
      'tag="web-bot-auth"',
      'tag=web-bot-auth',
    )
    await expectReason(
      plain({
        'signature-agent': signed.request.header('signature-agent') as string,
        'signature-input': input,
        signature: signed.request.header('signature') as string,
      }),
      'no_web_bot_auth_tag',
    )
  })

  it('missing_keyid', async () => {
    await expectReason((await sign({ keyid: null })).request, 'missing_keyid')
  })

  it('missing_created and missing_expires', async () => {
    const signed = await sign()
    const stripped = (drop: string): string =>
      (signed.request.header('signature-input') as string).replace(new RegExp(`;${drop}=\\d+`), '')
    for (const [param, reason] of [
      ['created', 'missing_created'],
      ['expires', 'missing_expires'],
    ] as const) {
      await expectReason(
        plain({
          'signature-agent': signed.request.header('signature-agent') as string,
          'signature-input': stripped(param),
          signature: signed.request.header('signature') as string,
        }),
        reason,
      )
    }
  })

  it('unsupported_algorithm when alg is not permitted', async () => {
    await expectReason((await sign({ alg: 'rsa-pss-sha512' })).request, 'unsupported_algorithm')
  })

  it('unsupported_algorithm when the resolved key is not Ed25519', async () => {
    const resolver: KeyResolver = {
      resolve: async (): Promise<KeyResolution> => ({
        ok: true,
        jwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' },
      }),
    }
    await expectReason(
      (await sign()).request,
      'unsupported_algorithm',
      verifierWith({ keys: resolver }),
    )
  })

  it('covered_components_insufficient when @authority is not covered', async () => {
    const signed = await sign({ components: ['"signature-agent"'] })
    await expectReason(signed.request, 'covered_components_insufficient')
  })

  // @target-uri contains the authority and pins more besides, so it satisfies
  // the requirement rather than failing it.
  it('accepts @target-uri in place of @authority', async () => {
    const signed = await sign({ components: ['"@target-uri"', '"signature-agent"'] })
    await expectReason(signed.request, 'ok')
  })

  it('covered_components_insufficient when Signature-Agent is sent but not covered', async () => {
    const signed = await sign({ components: ['"@authority"'] })
    expect(signed.request.header('signature-agent')).toBeDefined()
    await expectReason(signed.request, 'covered_components_insufficient')
  })

  it('signature_agent_malformed for a non-https or unquoted agent', async () => {
    const signed = await sign()
    for (const bad of ['"http://agent.example"', 'https://agent.example', '"/relative"']) {
      await expectReason(
        plain({
          'signature-agent': bad,
          'signature-input': signed.request.header('signature-input') as string,
          signature: signed.request.header('signature') as string,
        }),
        'signature_agent_malformed',
      )
    }
  })

  it('signature_agent_missing when the profile needs it to find a key', async () => {
    await expectReason((await sign({ signatureAgent: null })).request, 'signature_agent_missing')
  })

  it('signature_agent_not_allowed in allowlist mode', async () => {
    const verifier = verifierWith(
      { allowedOrigins: ['https://other.example'] },
      { [ORIGIN]: [key.publicJwk] },
    )
    const verdict = await expectReason(
      (await sign()).request,
      'signature_agent_not_allowed',
      verifier,
    )
    expect(verdict.class).toBe('untrusted')
  })

  it('validity_window_too_long beyond the profile ceiling', async () => {
    await expectReason((await sign({ expires: NOW + 86_401 })).request, 'validity_window_too_long')
  })

  it('validity_window_too_long when expires precedes created', async () => {
    await expectReason((await sign({ expires: NOW - 10 })).request, 'validity_window_too_long')
  })

  it('created_in_future beyond the skew allowance', async () => {
    await expectReason(
      (await sign({ created: NOW + 60, expires: NOW + 120 })).request,
      'created_in_future',
    )
  })

  it('accepts a created within the skew allowance', async () => {
    await expectReason((await sign({ created: NOW + 4, expires: NOW + 64 })).request, 'ok')
  })

  it('signature_expired', async () => {
    const verdict = await expectReason(
      (await sign({ created: NOW - 120, expires: NOW - 60 })).request,
      'signature_expired',
    )
    expect(verdict.class).toBe('expired')
  })

  it('signature_too_old even while still within expires', async () => {
    await expectReason(
      (await sign({ created: NOW - 3600, expires: NOW + 3600 })).request,
      'signature_too_old',
    )
  })

  it('covered_component_missing when a signed field is not sent', async () => {
    const signed = await sign({
      headers: { 'content-digest': 'sha-256=:abc:' },
      components: ['"@authority"', '"signature-agent"', '"content-digest"'],
    })
    const stripped = createRequest({
      method: 'GET',
      scheme: 'https',
      authority: 'example.com',
      path: '/',
      headers: {
        'signature-agent': signed.request.header('signature-agent') as string,
        'signature-input': signed.request.header('signature-input') as string,
        signature: signed.request.header('signature') as string,
      },
    })
    const verdict = await expectReason(stripped, 'covered_component_missing')
    expect(verdict.class).toBe('malformed')
  })

  // Our gap, not theirs: never reported as untrusted.
  it('unsupported_component for an RFC 9421 feature Badge lacks', async () => {
    const signed = await sign()
    const input = (signed.request.header('signature-input') as string).replace(
      '("@authority" "signature-agent")',
      '("@authority" "signature-agent";sf)',
    )
    const verdict = await expectReason(
      plain({
        'signature-agent': signed.request.header('signature-agent') as string,
        'signature-input': input,
        signature: signed.request.header('signature') as string,
      }),
      'unsupported_component',
    )
    expect(verdict.class).toBe('unverifiable')
  })

  it('key_not_found when no published key matches the thumbprint', async () => {
    const other = await generateSigningKey()
    const verdict = await expectReason(
      (await sign()).request,
      'key_not_found',
      verifierWith({}, { [ORIGIN]: [other.publicJwk] }),
    )
    expect(verdict.class).toBe('untrusted')
  })

  it('key_not_yet_valid and key_expired from the directory rotation window', async () => {
    for (const [overrides, reason] of [
      [{ nbf: NOW + 100 }, 'key_not_yet_valid'],
      [{ exp: NOW - 1 }, 'key_expired'],
    ] as const) {
      const rotating = await generateSigningKey(overrides)
      const signed = await signRequest({
        key: rotating,
        created: NOW,
        expires: NOW + 60,
      })
      await expectReason(
        signed.request,
        reason,
        verifierWith({}, { [ORIGIN]: [rotating.publicJwk] }),
      )
    }
  })

  it('signature_invalid on a tampered signature', async () => {
    const verdict = await expectReason(
      (await sign({ tamperSignature: true })).request,
      'signature_invalid',
    )
    expect(verdict.class).toBe('untrusted')
  })

  it('signature_invalid when the authority the client addressed differs', async () => {
    const signed = await sign({ authority: 'example.com' })
    const elsewhere = createRequest({
      method: 'GET',
      scheme: 'https',
      authority: 'internal-lb.example',
      path: '/',
      headers: {
        'signature-agent': signed.request.header('signature-agent') as string,
        'signature-input': signed.request.header('signature-input') as string,
        signature: signed.request.header('signature') as string,
      },
    })
    await expectReason(elsewhere, 'signature_invalid')
  })

  it.each([
    'directory_unreachable',
    'directory_timeout',
    'directory_malformed',
    'directory_too_large',
  ] satisfies ReasonCode[])('propagates %s from the resolver as unverifiable', async (reason) => {
    const resolver: KeyResolver = { resolve: async () => ({ ok: false, reason, cache: 'miss' }) }
    const verdict = await expectReason(
      (await sign()).request,
      reason,
      verifierWith({ keys: resolver }),
    )
    expect(verdict.class).toBe('unverifiable')
    expect(verdict.timing.cache).toBe('miss')
  })

  it('internal_error when the resolver throws, rather than leaking the exception', async () => {
    const resolver: KeyResolver = {
      resolve: async () => {
        throw new Error('boom')
      },
    }
    const verdict = await expectReason(
      (await sign()).request,
      'internal_error',
      verifierWith({ keys: resolver }),
    )
    expect(verdict.class).toBe('unverifiable')
  })
})

describe('replay protection', () => {
  const store = (seen = new Set<string>()): NonceStore => ({
    checkAndRecord: async (nonce) => {
      if (seen.has(nonce)) return false
      seen.add(nonce)
      return true
    },
  })

  it('works end to end with the shipped in-memory store', async () => {
    const verifier = verifierWith(
      { replay: memoryNonceStore({ clock: fixedClock(NOW) }) },
      { [ORIGIN]: [key.publicJwk] },
    )
    const signed = await sign({ nonce: true })
    expect((await verifier.verify(signed.request)).reason).toBe('ok')
    expect((await verifier.verify(signed.request)).reason).toBe('replay_detected')
  })

  it('reports a saturated store as unverifiable rather than as a replay', async () => {
    const verifier = verifierWith(
      { replay: memoryNonceStore({ clock: fixedClock(NOW), maxEntries: 1 }) },
      { [ORIGIN]: [key.publicJwk] },
    )
    expect((await verifier.verify((await sign({ nonce: true })).request)).reason).toBe('ok')
    const verdict = await verifier.verify((await sign({ nonce: true })).request)
    expect(verdict.reason).toBe('nonce_store_unavailable')
    expect(verdict.class).toBe('unverifiable')
  })

  it('is off by default, so a captured signature replays until it expires', async () => {
    const signed = await sign({ nonce: true })
    const verifier = defaultVerifier()
    expect((await verifier.verify(signed.request)).reason).toBe('ok')
    expect((await verifier.verify(signed.request)).reason).toBe('ok')
  })

  it('rejects a second use of the same nonce when enabled', async () => {
    const verifier = verifierWith({ replay: store() }, { [ORIGIN]: [key.publicJwk] })
    const signed = await sign({ nonce: true })
    expect((await verifier.verify(signed.request)).reason).toBe('ok')
    const second = await verifier.verify(signed.request)
    expect(second.reason).toBe('replay_detected')
    expect(second.class).toBe('untrusted')
  })

  it('requires a nonce when enabled', async () => {
    const verifier = verifierWith({ replay: store() }, { [ORIGIN]: [key.publicJwk] })
    expect((await verifier.verify((await sign()).request)).reason).toBe('nonce_missing')
  })

  // A short nonce is not merely weak. An attacker can enumerate the space and
  // pre-seed the store, turning replay protection into a denial of service
  // against the very signer it protects.
  it.each(['abc', '', 'not base64!!', 'c2hvcnQ='])(
    'rejects the unusable nonce %j',
    async (nonce) => {
      const verifier = verifierWith({ replay: store() }, { [ORIGIN]: [key.publicJwk] })
      const verdict = await verifier.verify((await sign({ nonce })).request)
      expect(verdict.reason).toBe('nonce_invalid')
      expect(verdict.class).toBe('malformed')
    },
  )

  it('accepts a nonce at the configured minimum', async () => {
    const verifier = verifierWith(
      { replay: store(), minNonceBytes: 8 },
      { [ORIGIN]: [key.publicJwk] },
    )
    const eightBytes = Buffer.from(new Uint8Array(8).fill(7)).toString('base64url')
    expect((await verifier.verify((await sign({ nonce: eightBytes })).request)).reason).toBe('ok')
  })

  it('can be tightened to the 64 bytes the reference implementation uses', async () => {
    const verifier = verifierWith(
      { replay: store(), minNonceBytes: 64 },
      { [ORIGIN]: [key.publicJwk] },
    )
    const thirtyTwo = Buffer.from(new Uint8Array(32).fill(7)).toString('base64url')
    expect((await verifier.verify((await sign({ nonce: thirtyTwo })).request)).reason).toBe(
      'nonce_invalid',
    )
    expect((await verifier.verify((await sign({ nonce: true })).request)).reason).toBe('ok')
  })

  it('ignores an unusable nonce entirely when replay protection is off', async () => {
    const verdict = await defaultVerifier().verify((await sign({ nonce: 'abc' })).request)
    expect(verdict.reason).toBe('ok')
  })

  // A Redis hiccup must not read as an attack.
  it('reports a store outage as unverifiable, not as a replay', async () => {
    const broken: NonceStore = {
      checkAndRecord: async () => {
        throw new Error('redis is down')
      },
    }
    const verifier = verifierWith({ replay: broken }, { [ORIGIN]: [key.publicJwk] })
    const verdict = await verifier.verify((await sign({ nonce: true })).request)
    expect(verdict.reason).toBe('nonce_store_unavailable')
    expect(verdict.class).toBe('unverifiable')
  })
})
