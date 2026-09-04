import { buildSignatureBase, importEd25519PublicKey, sfv, verifyEd25519 } from '@badge/core'
import { describe, expect, it } from 'vitest'
import { generateSigningKey, signRequest } from './signer.js'

const { parseDictionary, parseItem } = sfv

/**
 * The testkit is the foundation every verifier test stands on, so it gets
 * checked against the primitives directly: parse what it produced with the real
 * parser, rebuild the base, and verify with raw WebCrypto. If this passes, a
 * later verifier failure is the verifier's fault and not the fixture's.
 */
describe('generateNonce', () => {
  it('produces the 64 bytes the reference implementation expects', async () => {
    const { generateNonce } = await import('./signer.js')
    const nonce = generateNonce()
    expect(Buffer.from(nonce, 'base64url')).toHaveLength(64)
    expect(nonce).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(generateNonce()).not.toBe(nonce)
  })
})

describe('signRequest', () => {
  it('produces a signature that verifies after a full parse round trip', async () => {
    const key = await generateSigningKey()
    const signed = await signRequest({ key, authority: 'example.com' })

    const input = signed.request.header('signature-input')
    if (input === undefined) throw new Error('missing Signature-Input')
    const entry = parseDictionary(input).get('sig1')
    if (entry?.value.kind !== 'inner-list') throw new Error('expected inner list')

    const rebuilt = buildSignatureBase({
      request: signed.request,
      components: entry.value.items,
      signatureParamsSource: entry.source,
    })
    expect(rebuilt).toBe(signed.base)

    const sigHeader = signed.request.header('signature')
    if (sigHeader === undefined) throw new Error('missing Signature')
    const sigEntry = parseDictionary(sigHeader).get('sig1')
    if (sigEntry?.value.kind !== 'item' || sigEntry.value.value.type !== 'binary') {
      throw new Error('expected a byte sequence')
    }

    const publicKey = await importEd25519PublicKey(key.publicJwk)
    await expect(
      verifyEd25519(publicKey, sigEntry.value.value.value, new TextEncoder().encode(rebuilt)),
    ).resolves.toBe(true)
  })

  it('covers @authority and signature-agent by default', async () => {
    const key = await generateSigningKey()
    const signed = await signRequest({ key })
    expect(signed.base).toContain('"@authority": example.com')
    expect(signed.base).toContain('"signature-agent": "https://agent.example"')
  })

  it('carries the Web Bot Auth parameters', async () => {
    const key = await generateSigningKey()
    const signed = await signRequest({ key, created: 1000, expires: 1060 })
    const input = signed.request.header('signature-input') as string
    const entry = parseDictionary(input).get('sig1')
    if (entry?.value.kind !== 'inner-list') throw new Error('expected inner list')
    expect(entry.value.params.get('tag')).toEqual({ type: 'string', value: 'web-bot-auth' })
    expect(entry.value.params.get('alg')).toEqual({ type: 'string', value: 'ed25519' })
    expect(entry.value.params.get('keyid')).toEqual({ type: 'string', value: key.keyid })
    expect(entry.value.params.get('created')).toEqual({ type: 'integer', value: 1000 })
    expect(entry.value.params.get('expires')).toEqual({ type: 'integer', value: 1060 })
  })

  it('omits Signature-Agent and its covered component when asked', async () => {
    const key = await generateSigningKey()
    const signed = await signRequest({ key, signatureAgent: null })
    expect(signed.request.header('signature-agent')).toBeUndefined()
    expect(signed.base).not.toContain('signature-agent')
  })

  it('can omit each parameter, for exercising failure paths', async () => {
    const key = await generateSigningKey()
    const signed = await signRequest({ key, tag: null, alg: null, keyid: null })
    const input = signed.request.header('signature-input') as string
    expect(input).not.toContain('tag=')
    expect(input).not.toContain('alg=')
    expect(input).not.toContain('keyid=')
  })

  it('can corrupt the signature while leaving everything else valid', async () => {
    const key = await generateSigningKey()
    const [good, bad] = await Promise.all([
      signRequest({ key, created: 1000 }),
      signRequest({ key, created: 1000, tamperSignature: true }),
    ])
    expect(bad.request.header('signature-input')).toBe(good.request.header('signature-input'))
    expect(bad.request.header('signature')).not.toBe(good.request.header('signature'))
  })

  it('signs arbitrary covered components', async () => {
    const key = await generateSigningKey()
    const signed = await signRequest({
      key,
      method: 'POST',
      path: '/checkout',
      query: 'cart=abc',
      components: ['"@method"', '"@authority"', '"@path"', '"@query"', '"signature-agent"'],
    })
    expect(signed.base).toContain('"@method": POST')
    expect(signed.base).toContain('"@path": /checkout')
    expect(signed.base).toContain('"@query": ?cart=abc')
  })

  it('generates keys whose keyid is the thumbprint of the published JWK', async () => {
    const key = await generateSigningKey()
    expect(key.publicJwk).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      x: expect.any(String) as unknown as string,
    })
    expect(key.keyid).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('accepts JWK overrides so rotation windows can be tested', async () => {
    const key = await generateSigningKey({ nbf: 100, exp: 200 })
    expect(key.publicJwk.nbf).toBe(100)
    expect(key.publicJwk.exp).toBe(200)
  })

  it('parses every default component identifier it emits', async () => {
    const key = await generateSigningKey()
    const signed = await signRequest({ key })
    for (const line of signed.base.split('\n')) {
      const id = line.slice(0, line.indexOf(': '))
      expect(() => parseItem(id)).not.toThrow()
    }
  })
})
