import type { webcrypto } from 'node:crypto'
import { createVerifier, jwkThumbprint, staticKeyResolver, type Jwk } from '@badge/core'
import { fromFetchRequest } from '@badge/adapters'
import { generateNonce, generateSigningKey, signRequest, type SigningKey } from '@badge/testkit'
import {
  HTTP_MESSAGE_SIGNATURES_DIRECTORY,
  HTTP_MESSAGE_SIGNATURE_TAG,
  jwkToKeyID,
  sign as referenceSign,
  verify as referenceVerify,
} from 'web-bot-auth'
import { beforeAll, describe, expect, it } from 'vitest'
import { referenceSigner, referenceVerifier } from './index.js'

/**
 * Badge against the Cloudflare `web-bot-auth` reference implementation, in both
 * directions.
 *
 * Every other test in this repository verifies a signature that Badge itself
 * produced. A consistent misreading of the drafts would pass all of them. These
 * do not have that property: the counterparty is written by the draft's own
 * author, against the same specification, and neither side has seen the other's
 * code.
 */

const NOW = 1_735_689_600
const AUTHORITY = 'example.com'
const AGENT_ORIGIN = 'https://agent.example'

let key: SigningKey
let keyid: string

beforeAll(async () => {
  key = await generateSigningKey()
  keyid = key.keyid
})

const created = new Date(NOW * 1000)
const expires = new Date((NOW + 60) * 1000)

const badgeVerifier = (keys: Jwk[] = [key.publicJwk]) =>
  createVerifier({
    keys: staticKeyResolver({ [AGENT_ORIGIN]: keys }),
    clock: { now: () => NOW },
  })

/** Sign a request with the reference implementation and return it with its headers applied. */
const signWithReference = async (
  url: string,
  extra: Record<string, unknown> = {},
): Promise<Request> => {
  const request = new Request(url, { headers: { 'signature-agent': `"${AGENT_ORIGIN}"` } })
  const fields = await referenceSign(request, {
    signer: referenceSigner(key.privateKey as unknown as webcrypto.CryptoKey, keyid),
    created,
    expires,
    ...extra,
  })
  const headers = new Headers(request.headers)
  headers.set('signature-input', fields.signatureInput)
  headers.set('signature', fields.signature)
  return new Request(url, { headers })
}

describe('constants agree', () => {
  it('uses the same tag', () => {
    expect(HTTP_MESSAGE_SIGNATURE_TAG).toBe('web-bot-auth')
  })

  it('uses the same well-known directory path', () => {
    expect(HTTP_MESSAGE_SIGNATURES_DIRECTORY).toBe('/.well-known/http-message-signatures-directory')
  })
})

describe('key thumbprints agree', () => {
  const toKeyId = async (jwk: Jwk): Promise<string> =>
    await jwkToKeyID(
      jwk as unknown as JsonWebKey,
      async (bytes: Uint8Array) => await crypto.subtle.digest('SHA-256', bytes),
      (bytes: ArrayBuffer) => Buffer.from(new Uint8Array(bytes)).toString('base64url'),
    )

  it('computes the same keyid for freshly generated keys', async () => {
    for (let i = 0; i < 5; i += 1) {
      const generated = await generateSigningKey()
      expect(await jwkThumbprint(generated.publicJwk)).toBe(await toKeyId(generated.publicJwk))
    }
  })

  // RFC 8037 Appendix A.3. Both implementations must land on the published value.
  it('agrees with each other and with the RFC on the published vector', async () => {
    const jwk: Jwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
    }
    const expected = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k'
    expect(await jwkThumbprint(jwk)).toBe(expected)
    expect(await toKeyId(jwk)).toBe(expected)
  })
})

describe('the reference signs, Badge verifies', () => {
  it('accepts a default web-bot-auth signature', async () => {
    const signed = await signWithReference(`https://${AUTHORITY}/docs/intro`)
    const verdict = await badgeVerifier().verify(fromFetchRequest(signed))
    expect(verdict.reason).toBe('ok')
    expect(verdict.status).toBe('verified')
    expect(verdict.keyid).toBe(keyid)
    expect(verdict.signatureAgent).toBe(AGENT_ORIGIN)
  })

  /**
   * The reference orders signature parameters `created;keyid;alg;expires;tag`,
   * while Badge's own signer emits `created;expires;keyid;alg;tag`. Badge
   * reconstructs `@signature-params` from the received bytes rather than
   * re-serializing its parse tree, which is exactly why a different ordering
   * verifies instead of failing as `signature_invalid`.
   */
  it('accepts parameters in an order Badge would not have chosen', async () => {
    const signed = await signWithReference(`https://${AUTHORITY}/docs/intro`)
    const input = signed.headers.get('signature-input') ?? ''
    expect(input.indexOf(';alg=')).toBeLessThan(input.indexOf(';expires='))
    expect(await badgeVerifier().verify(fromFetchRequest(signed))).toMatchObject({ reason: 'ok' })
  })

  it('accepts a signature over @target-uri instead of @authority', async () => {
    const signed = await signWithReference(`https://${AUTHORITY}/docs/intro?a=1`, {
      target: '@target-uri',
    })
    expect(signed.headers.get('signature-input')).toContain('"@target-uri"')
    const verdict = await badgeVerifier().verify(fromFetchRequest(signed))
    expect(verdict.reason).toBe('ok')
  })

  it('accepts a nonce it was not asked to check', async () => {
    const signed = await signWithReference(`https://${AUTHORITY}/docs/intro`, {
      nonce: generateNonce(),
    })
    expect(signed.headers.get('signature-input')).toContain(';nonce=')
    expect(await badgeVerifier().verify(fromFetchRequest(signed))).toMatchObject({ reason: 'ok' })
  })

  it('rejects a reference-signed request whose key it does not hold', async () => {
    const other = await generateSigningKey()
    const signed = await signWithReference(`https://${AUTHORITY}/docs/intro`)
    expect(await badgeVerifier([other.publicJwk]).verify(fromFetchRequest(signed))).toMatchObject({
      reason: 'key_not_found',
    })
  })

  it('rejects a reference-signed request that was altered in flight', async () => {
    const signed = await signWithReference(`https://${AUTHORITY}/docs/intro`)
    const moved = new Request(`https://evil.example/docs/intro`, { headers: signed.headers })
    expect(await badgeVerifier().verify(fromFetchRequest(moved))).toMatchObject({
      reason: 'signature_invalid',
    })
  })
})

describe('Badge signs, the reference verifies', () => {
  const verifyWithReference = async (headers: Record<string, string>, url: string) =>
    await referenceVerify(new Request(url, { headers }), {
      resolver: async () => await referenceVerifier(key.publicJwk, keyid),
      now: created,
    })

  it('accepts a Badge signature', async () => {
    const signed = await signRequest({
      key,
      authority: AUTHORITY,
      path: '/docs/intro',
      created: NOW,
      expires: NOW + 60,
      signatureAgent: AGENT_ORIGIN,
    })
    const result = await verifyWithReference(signed.headers, `https://${AUTHORITY}/docs/intro`)
    expect(result.keyid).toBe(keyid)
    expect(result.tag).toBe('web-bot-auth')
  })

  it('accepts a Badge signature carrying a nonce', async () => {
    const signed = await signRequest({
      key,
      authority: AUTHORITY,
      path: '/docs/intro',
      created: NOW,
      expires: NOW + 60,
      signatureAgent: AGENT_ORIGIN,
      nonce: true,
    })
    const result = await verifyWithReference(signed.headers, `https://${AUTHORITY}/docs/intro`)
    expect(result.nonce).toMatch(/^[A-Za-z0-9_-]{86}$/)
  })

  it('rejects a tampered Badge signature', async () => {
    const signed = await signRequest({
      key,
      authority: AUTHORITY,
      path: '/docs/intro',
      created: NOW,
      expires: NOW + 60,
      signatureAgent: AGENT_ORIGIN,
      tamperSignature: true,
    })
    await expect(
      verifyWithReference(signed.headers, `https://${AUTHORITY}/docs/intro`),
    ).rejects.toThrow()
  })
})
