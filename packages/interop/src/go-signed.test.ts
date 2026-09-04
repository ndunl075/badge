import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { createRequest, createVerifier, staticKeyResolver, type Jwk } from '@badge/core'
import { verify as referenceVerify } from 'web-bot-auth'
import { describe, expect, it } from 'vitest'
import { referenceVerifier } from './index.js'

/**
 * Requests signed by the Go sidecar, verified here by both the TypeScript
 * implementation and the Cloudflare reference implementation.
 *
 * This is the widest cross-check in the project. The Go implementation produced
 * these bytes; two other implementations that share no code with it — and one
 * of which was written by the draft's own author — accept them. Agreement
 * between three independent implementations on real signatures is a
 * substantially stronger claim than agreement on a reading of the prose.
 *
 * The key is RFC 8037 Appendix A.1 and Ed25519 is deterministic, so the file is
 * stable. Regenerate with `go run ./cmd/gen-vectors` from `sidecar/`.
 */

interface GoSignedVector {
  readonly name: string
  readonly request: {
    readonly method: string
    readonly scheme: 'http' | 'https'
    readonly authority: string
    readonly path: string
    readonly query: string
  }
  readonly headers: Record<string, string>
  readonly base: string
}

interface GoSignedDocument {
  readonly now: number
  readonly profile: string
  readonly signatureAgentOrigin: string
  readonly keyid: string
  readonly publishedKeys: Jwk[]
  readonly vectors: GoSignedVector[]
}

const doc = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../../../spec-vectors/go-signed.json', import.meta.url)),
    'utf8',
  ),
) as GoSignedDocument

const asRequest = (vector: GoSignedVector) =>
  createRequest({
    method: vector.request.method,
    scheme: vector.request.scheme,
    authority: vector.request.authority,
    path: vector.request.path,
    query: vector.request.query,
    headers: vector.headers,
  })

describe('the Go sidecar signs, TypeScript verifies', () => {
  const verifier = createVerifier({
    keys: staticKeyResolver({ [doc.signatureAgentOrigin]: doc.publishedKeys }),
    clock: { now: () => doc.now },
  })

  it('loads the committed fixtures', () => {
    expect(doc.vectors.length).toBeGreaterThan(0)
    expect(doc.keyid).toBe('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k')
  })

  it.each(doc.vectors.map((v) => [v.name, v] as const))('%s', async (_name, vector) => {
    const verdict = await verifier.verify(asRequest(vector))
    expect(verdict.reason).toBe('ok')
    expect(verdict.keyid).toBe(doc.keyid)
    expect(verdict.signatureAgent).toBe(doc.signatureAgentOrigin)
  })

  it('rejects a Go-signed request moved to another authority', async () => {
    const vector = doc.vectors[0] as GoSignedVector
    const moved = createRequest({
      method: vector.request.method,
      scheme: vector.request.scheme,
      authority: 'evil.example',
      path: vector.request.path,
      query: vector.request.query,
      headers: vector.headers,
    })
    expect((await verifier.verify(moved)).reason).toBe('signature_invalid')
  })
})

describe('the Go sidecar signs, the reference implementation verifies', () => {
  const toUrl = (vector: GoSignedVector): string => {
    const query = vector.request.query === '' ? '' : `?${vector.request.query}`
    return `${vector.request.scheme}://${vector.request.authority}${vector.request.path}${query}`
  }

  it.each(doc.vectors.map((v) => [v.name, v] as const))('%s', async (_name, vector) => {
    const key = doc.publishedKeys[0] as Jwk
    const result = await referenceVerify(
      new Request(toUrl(vector), {
        method: vector.request.method,
        headers: vector.headers,
      }),
      {
        resolver: async () => await referenceVerifier(key, doc.keyid),
        now: new Date(doc.now * 1000),
      },
    )
    expect(result.keyid).toBe(doc.keyid)
    expect(result.tag).toBe('web-bot-auth')
  })
})
