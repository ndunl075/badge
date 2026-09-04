import { importEd25519PublicKey, verifyEd25519, type Jwk } from '@badge/core'

/**
 * Bridges between Badge and the Cloudflare `web-bot-auth` reference
 * implementation, so the two can check each other.
 *
 * Until this package existed, every signature Badge verified was a signature
 * Badge had produced. That is a closed loop: a consistent misreading of the
 * drafts would pass every test in the repository. The hand-written vectors in
 * `spec-vectors/` narrow the gap, but they are still one person's reading of
 * the spec. This package closes it against an implementation written by the
 * draft's own author.
 */

/** The `Verifier` shape the reference implementation expects, backed by Badge's crypto. */
export interface ReferenceVerifier {
  readonly algorithm: 'ed25519'
  readonly keyid: string
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>
}

export async function referenceVerifier(jwk: Jwk, keyid: string): Promise<ReferenceVerifier> {
  const key = await importEd25519PublicKey(jwk)
  return {
    algorithm: 'ed25519',
    keyid,
    verify: async (data, signature) => await verifyEd25519(key, signature, data),
  }
}

/** The `Signer` shape the reference implementation expects, backed by a raw private key. */
export interface ReferenceSigner {
  readonly algorithm: 'ed25519'
  readonly keyid: string
  sign(data: Uint8Array): Promise<Uint8Array>
}

export function referenceSigner(
  privateKey: Parameters<typeof crypto.subtle.sign>[1],
  keyid: string,
): ReferenceSigner {
  return {
    algorithm: 'ed25519',
    keyid,
    // The reference passes the signature base as bytes, already encoded.
    // Encoding it a second time is an easy and silent way to produce a
    // signature over the wrong thing.
    sign: async (data) =>
      new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, data)),
  }
}
