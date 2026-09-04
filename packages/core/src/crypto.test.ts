import { describe, expect, it } from 'vitest'
import {
  KeyError,
  base64UrlDecode,
  base64UrlEncode,
  canonicalJwkJson,
  importEd25519PublicKey,
  isEd25519,
  jwkThumbprint,
  keyValidityAt,
  toPublicJwk,
  verifyEd25519,
  type Jwk,
} from './crypto.js'

/** RFC 8037 Appendix A.3. */
const RFC8037_KEY: Jwk = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
}
const RFC8037_THUMBPRINT = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k'

describe('canonicalJwkJson', () => {
  it('orders members lexicographically per key type', () => {
    expect(canonicalJwkJson(RFC8037_KEY)).toBe(
      '{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}',
    )
    expect(canonicalJwkJson({ kty: 'RSA', n: 'abc', e: 'AQAB' })).toBe(
      '{"e":"AQAB","kty":"RSA","n":"abc"}',
    )
    expect(canonicalJwkJson({ kty: 'EC', crv: 'P-256', x: 'xx', y: 'yy' })).toBe(
      '{"crv":"P-256","kty":"EC","x":"xx","y":"yy"}',
    )
    expect(canonicalJwkJson({ kty: 'oct', k: 'kk' })).toBe('{"k":"kk","kty":"oct"}')
  })

  it('excludes every member that is not required', () => {
    const noisy: Jwk = {
      ...RFC8037_KEY,
      kid: 'ignored',
      alg: 'Ed25519',
      use: 'sig',
      key_ops: ['verify'],
      nbf: 1,
      exp: 2,
    }
    expect(canonicalJwkJson(noisy)).toBe(canonicalJwkJson(RFC8037_KEY))
  })

  it.each([
    ['an unknown key type', { kty: 'MAGIC' }],
    ['a missing member', { kty: 'OKP', crv: 'Ed25519' }],
    ['an empty member', { kty: 'OKP', crv: 'Ed25519', x: '' }],
  ])('rejects %s', (_label, jwk) => {
    expect(() => canonicalJwkJson(jwk as Jwk)).toThrow(KeyError)
  })
})

describe('jwkThumbprint', () => {
  // Known answer from RFC 8037 Appendix A.3. If this drifts, Badge's keyid
  // matching silently disagrees with every other implementation.
  it('matches the RFC 8037 vector', async () => {
    await expect(jwkThumbprint(RFC8037_KEY)).resolves.toBe(RFC8037_THUMBPRINT)
  })

  it('is unaffected by a directory-asserted kid', async () => {
    await expect(jwkThumbprint({ ...RFC8037_KEY, kid: 'something-else' })).resolves.toBe(
      RFC8037_THUMBPRINT,
    )
  })
})

describe('Ed25519 verification', () => {
  const generate = async (): Promise<CryptoKeyPair> =>
    (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair

  const publicJwk = async (pair: CryptoKeyPair): Promise<Jwk> =>
    (await crypto.subtle.exportKey('jwk', pair.publicKey)) as Jwk

  it('verifies a signature made by the matching key', async () => {
    const pair = await generate()
    const data = new TextEncoder().encode('"@authority": example.com')
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, data))
    const key = await importEd25519PublicKey(await publicJwk(pair))
    await expect(verifyEd25519(key, sig, data)).resolves.toBe(true)
  })

  it('rejects a tampered message', async () => {
    const pair = await generate()
    const data = new TextEncoder().encode('"@authority": example.com')
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, data))
    const key = await importEd25519PublicKey(await publicJwk(pair))
    const tampered = new TextEncoder().encode('"@authority": evil.example')
    await expect(verifyEd25519(key, sig, tampered)).resolves.toBe(false)
  })

  it('rejects a signature from a different key', async () => {
    const [signer, other] = [await generate(), await generate()]
    const data = new TextEncoder().encode('base')
    const sig = new Uint8Array(
      await crypto.subtle.sign({ name: 'Ed25519' }, signer.privateKey, data),
    )
    const key = await importEd25519PublicKey(await publicJwk(other))
    await expect(verifyEd25519(key, sig, data)).resolves.toBe(false)
  })

  // Some runtimes throw on a wrong-length signature and others return false.
  // Both mean "not verified"; neither should propagate as an internal error.
  it('returns false rather than throwing on a malformed signature', async () => {
    const pair = await generate()
    const key = await importEd25519PublicKey(await publicJwk(pair))
    await expect(verifyEd25519(key, new Uint8Array([1, 2, 3]), new Uint8Array())).resolves.toBe(
      false,
    )
  })

  it('refuses to import a non-Ed25519 key', async () => {
    await expect(
      importEd25519PublicKey({ kty: 'EC', crv: 'P-256', x: 'a', y: 'b' }),
    ).rejects.toThrow(KeyError)
  })

  it('recognizes Ed25519 keys', () => {
    expect(isEd25519(RFC8037_KEY)).toBe(true)
    expect(isEd25519({ kty: 'OKP', crv: 'X25519', x: 'a' })).toBe(false)
    expect(isEd25519({ kty: 'EC', crv: 'Ed25519', x: 'a' })).toBe(false)
  })
})

describe('toPublicJwk', () => {
  // Deleting `d` from an exported private key leaves `key_ops: ["sign"]` and
  // `ext: true` behind: a public key advertising that it can sign. Enumerating
  // what may be published cannot fail that way.
  it('keeps only public members', () => {
    const exported = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'abc',
      d: 'SECRET',
      key_ops: ['sign'],
      ext: true,
      kid: 'k',
      nbf: 1,
      exp: 2,
    } as unknown as Jwk
    expect(toPublicJwk(exported)).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'abc',
      kid: 'k',
      nbf: 1,
      exp: 2,
    })
  })

  it('drops every private member of every key type', () => {
    const leaky = {
      kty: 'RSA',
      n: 'n',
      e: 'e',
      d: 'd',
      p: 'p',
      q: 'q',
      dp: 'dp',
      dq: 'dq',
      qi: 'qi',
    } as unknown as Jwk
    expect(toPublicJwk(leaky)).toEqual({ kty: 'RSA', n: 'n', e: 'e' })
  })

  it('leaves an already-public key alone', () => {
    expect(toPublicJwk(RFC8037_KEY)).toEqual(RFC8037_KEY)
  })
})

describe('keyValidityAt', () => {
  it('treats nbf as inclusive and exp as exclusive', () => {
    const key: Jwk = { ...RFC8037_KEY, nbf: 100, exp: 200 }
    expect(keyValidityAt(key, 99)).toBe('not-yet-valid')
    expect(keyValidityAt(key, 100)).toBe('valid')
    expect(keyValidityAt(key, 199)).toBe('valid')
    expect(keyValidityAt(key, 200)).toBe('expired')
  })

  it('treats an unbounded key as always valid', () => {
    expect(keyValidityAt(RFC8037_KEY, 0)).toBe('valid')
  })
})

describe('base64url', () => {
  it('round trips and omits padding', () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0x00, 0x10])
    const encoded = base64UrlEncode(bytes)
    expect(encoded).not.toContain('=')
    expect(encoded).not.toMatch(/[+/]/)
    expect([...base64UrlDecode(encoded)]).toEqual([...bytes])
  })

  it('round trips every byte value', () => {
    const bytes = new Uint8Array(256).map((_, i) => i)
    expect([...base64UrlDecode(base64UrlEncode(bytes))]).toEqual([...bytes])
  })

  it('rejects non-base64url input', () => {
    expect(() => base64UrlDecode('has+plus')).toThrow(KeyError)
    expect(() => base64UrlDecode('has/slash')).toThrow(KeyError)
  })
})
