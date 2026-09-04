import type { Jwk } from '@badge/core'
import type { SigningKey } from './signer.js'

/** The JWKS body a key directory serves. */
export interface KeyDirectory {
  readonly keys: readonly Jwk[]
}

export function keyDirectory(...keys: readonly (SigningKey | Jwk)[]): KeyDirectory {
  return {
    keys: keys.map((k) => ('publicJwk' in k ? k.publicJwk : k)),
  }
}
