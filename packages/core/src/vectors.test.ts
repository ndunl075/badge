import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { buildSignatureBase } from './base.js'
import type { Jwk } from './crypto.js'
import { staticKeyResolver } from './keys.js'
import { createRequest } from './request.js'
import { parseItem } from './sfv/parse.js'
import { createVerifier } from './verifier.js'

/**
 * Cross-implementation fixtures (ARCHITECTURE.md §16).
 *
 * The expected bases in `spec-vectors/` are written by hand rather than
 * generated from this code, so they are an independent statement of what the
 * bytes must be. Any port of Badge — the Go sidecar in §19, say — is expected
 * to reproduce them exactly, and a disagreement here means one of the two
 * implementations is wrong rather than merely different.
 */

interface BaseVector {
  readonly name: string
  readonly request: {
    readonly method: string
    readonly scheme: 'http' | 'https'
    readonly authority: string
    readonly path: string
    readonly query: string
    readonly headers: Record<string, string | string[]>
  }
  readonly components: readonly string[]
  readonly signatureParams: string
  readonly base: string
}

const vectorsPath = fileURLToPath(
  new URL('../../../spec-vectors/signature-base.json', import.meta.url),
)
const { vectors } = JSON.parse(readFileSync(vectorsPath, 'utf8')) as { vectors: BaseVector[] }

describe('signature base vectors', () => {
  it('loads the shared fixtures', () => {
    expect(vectors.length).toBeGreaterThan(0)
  })

  it.each(vectors.map((v) => [v.name, v] as const))('%s', (_name, vector) => {
    const request = createRequest({
      method: vector.request.method,
      scheme: vector.request.scheme,
      authority: vector.request.authority,
      path: vector.request.path,
      query: vector.request.query,
      headers: vector.request.headers,
    })
    const base = buildSignatureBase({
      request,
      components: vector.components.map((id) => parseItem(id)),
      signatureParamsSource: vector.signatureParams,
    })
    expect(base).toBe(vector.base)
  })

  it('never emits a trailing newline', () => {
    for (const vector of vectors) expect(vector.base.endsWith('\n')).toBe(false)
  })
})

interface VerdictVector {
  readonly name: string
  readonly request: {
    readonly method: string
    readonly scheme: 'http' | 'https'
    readonly authority: string
    readonly path: string
    readonly query: string
    readonly headers: Record<string, string>
  }
  readonly expect: { readonly status: string; readonly class: string; readonly reason: string }
}

interface VerdictDocument {
  readonly now: number
  readonly profile: string
  readonly signatureAgentOrigin: string
  readonly publishedKeys: Jwk[]
  readonly unrelatedKey: Jwk
  readonly vectors: VerdictVector[]
}

const verdictDoc = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../../../spec-vectors/verdicts.json', import.meta.url)),
    'utf8',
  ),
) as VerdictDocument

/**
 * End-to-end verifier vectors, signed with the fixed RFC 8037 Appendix A.1 key.
 *
 * Ed25519 is deterministic, so regenerating these produces byte-identical
 * output unless behaviour actually changed. That makes a diff in the fixture
 * file a signal rather than noise.
 */
describe('verdict vectors', () => {
  const verifier = (keys: Jwk[]) =>
    createVerifier({
      keys: staticKeyResolver({ [verdictDoc.signatureAgentOrigin]: keys }),
      clock: { now: () => verdictDoc.now },
    })

  it.each(verdictDoc.vectors.map((v) => [v.name, v] as const))('%s', async (_name, vector) => {
    const request = createRequest(vector.request)
    const verdict = await verifier(verdictDoc.publishedKeys).verify(request)
    expect({ status: verdict.status, class: verdict.class, reason: verdict.reason }).toEqual(
      vector.expect,
    )
    expect(verdict.profile).toBe(verdictDoc.profile)
  })

  it('reports key_not_found when the directory publishes an unrelated key', async () => {
    const valid = verdictDoc.vectors.find((v) => v.expect.reason === 'ok')
    if (valid === undefined) throw new Error('no valid vector')
    const verdict = await verifier([verdictDoc.unrelatedKey]).verify(createRequest(valid.request))
    expect(verdict.reason).toBe('key_not_found')
  })
})
