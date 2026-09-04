import type { Jwk } from '@badge/core'
import { generateSigningKey, type SigningKey } from '@badge/testkit'
import { beforeAll, describe, expect, it } from 'vitest'
import { DirectoryPublishError, buildDirectory, rotationWarnings } from './serve.js'

let key: SigningKey

beforeAll(async () => {
  key = await generateSigningKey()
})

describe('buildDirectory', () => {
  it('serves a JWKS at the well-known path with the mandated media type', async () => {
    const doc = await buildDirectory({ keys: [key.publicJwk] })
    expect(doc.path).toBe('/.well-known/http-message-signatures-directory')
    expect(doc.headers['content-type']).toBe('application/http-message-signatures-directory+json')
    expect(doc.headers['cache-control']).toBe('public, max-age=3600')
    expect(JSON.parse(doc.body)).toMatchObject({ keys: [{ kty: 'OKP', crv: 'Ed25519' }] })
  })

  it('publishes each key with its thumbprint as kid', async () => {
    const doc = await buildDirectory({ keys: [key.publicJwk] })
    const published = (JSON.parse(doc.body) as { keys: Jwk[] }).keys[0]
    expect(published?.kid).toBe(key.keyid)
  })

  it('preserves the rotation window', async () => {
    const rotating = await generateSigningKey({ nbf: 100, exp: 200 })
    const doc = await buildDirectory({ keys: [rotating.publicJwk] })
    expect((JSON.parse(doc.body) as { keys: Jwk[] }).keys[0]).toMatchObject({ nbf: 100, exp: 200 })
  })

  // The one place in Badge where a mistake leaks a signing key to the internet.
  it.each(['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'])(
    'refuses to publish a key carrying the private member %s',
    async (member) => {
      const leaky = { ...key.publicJwk, [member]: 'secret' } as Jwk
      await expect(buildDirectory({ keys: [leaky] })).rejects.toThrow(DirectoryPublishError)
    },
  )

  it('names the offending key in the error', async () => {
    const leaky = { ...key.publicJwk, d: 'secret' } as Jwk
    await expect(buildDirectory({ keys: [key.publicJwk, leaky] })).rejects.toThrow(/keys\[1\]/)
  })

  it('refuses a non-Ed25519 key by default, since verifiers ignore it', async () => {
    const rsa: Jwk = { kty: 'RSA', n: 'abc', e: 'AQAB' }
    await expect(buildDirectory({ keys: [rsa] })).rejects.toThrow(DirectoryPublishError)
  })

  it('publishes one anyway when explicitly asked', async () => {
    const rsa: Jwk = { kty: 'RSA', n: 'abc', e: 'AQAB' }
    const doc = await buildDirectory({ keys: [rsa], allowNonEd25519: true })
    expect((JSON.parse(doc.body) as { keys: Jwk[] }).keys).toHaveLength(1)
  })

  it('rejects a key with no kty', async () => {
    await expect(buildDirectory({ keys: [{} as Jwk] })).rejects.toThrow(DirectoryPublishError)
  })

  it('produces a document the resolver can parse', async () => {
    const doc = await buildDirectory({ keys: [key.publicJwk] })
    const parsed = JSON.parse(doc.body) as { keys: Jwk[] }
    expect(Array.isArray(parsed.keys)).toBe(true)
  })
})

describe('rotationWarnings', () => {
  const at = 1000

  it('is quiet for a healthy overlap', async () => {
    const current = await generateSigningKey({ exp: at + 500 })
    const next = await generateSigningKey({ nbf: at - 100 })
    expect(rotationWarnings([current.publicJwk, next.publicJwk], at)).toEqual([])
  })

  it('warns when nothing published is valid right now', async () => {
    const expired = await generateSigningKey({ exp: at - 1 })
    expect(rotationWarnings([expired.publicJwk], at).join(' ')).toContain('No published key')
  })

  it('points out a key that can be removed', async () => {
    const expired = await generateSigningKey({ exp: at - 1 })
    const live = await generateSigningKey()
    expect(rotationWarnings([expired.publicJwk, live.publicJwk], at).join(' ')).toContain(
      'can be removed',
    )
  })

  it('points out a window that is never valid', async () => {
    const broken = await generateSigningKey({ nbf: at + 100, exp: at + 100 })
    expect(rotationWarnings([broken.publicJwk], at).join(' ')).toContain('never valid')
  })

  it('says nothing about an empty directory', () => {
    expect(rotationWarnings([], at)).toEqual([])
  })
})
