import { jwkThumbprint, type Jwk } from './crypto.js'
import type { ReasonCode } from './reasons.js'

/** Where the resolved key came from, recorded in the verdict for diagnosis. */
export type CacheResult = 'hit' | 'stale' | 'miss'

export interface KeyRequest {
  /** Normalized `https` origin taken from `Signature-Agent`, e.g. `https://agent.example`. */
  readonly origin: string | undefined
  /** RFC 7638 thumbprint the caller presented. */
  readonly keyid: string
  /** Unix seconds, from the verifier's clock. */
  readonly now: number
}

export type KeyResolution =
  | { readonly ok: true; readonly jwk: Jwk; readonly cache?: CacheResult }
  | { readonly ok: false; readonly reason: ReasonCode; readonly cache?: CacheResult }

/**
 * Finds the public key a `keyid` refers to.
 *
 * This is the only part of verification that may do I/O, and it is an interface
 * precisely so that the network implementation — with its caches, timeouts, and
 * SSRF guard — stays out of the verifier and can be swapped for a static key
 * set or a test double.
 */
export interface KeyResolver {
  resolve(request: KeyRequest): Promise<KeyResolution>
}

/**
 * A resolver over a fixed set of keys, with no network access at all.
 *
 * Useful for pre-registered partners, for air-gapped deployments, and for
 * tests. Keys are indexed by origin; pass `'*'` to accept a key regardless of
 * which origin the caller named.
 */
export function staticKeyResolver(
  keysByOrigin: Readonly<Record<string, readonly Jwk[]>>,
): KeyResolver {
  // Thumbprints are computed once, on first use, then reused.
  const indexed = new Map<string, Map<string, Jwk>>()
  const indexFor = async (origin: string): Promise<Map<string, Jwk>> => {
    const cached = indexed.get(origin)
    if (cached !== undefined) return cached
    const index = new Map<string, Jwk>()
    for (const jwk of keysByOrigin[origin] ?? []) index.set(await jwkThumbprint(jwk), jwk)
    indexed.set(origin, index)
    return index
  }

  return {
    async resolve({ origin, keyid }) {
      for (const candidate of [...(origin === undefined ? [] : [origin]), '*']) {
        const jwk = (await indexFor(candidate)).get(keyid)
        if (jwk !== undefined) return { ok: true, jwk, cache: 'hit' }
      }
      return { ok: false, reason: 'key_not_found', cache: 'hit' }
    },
  }
}

/**
 * Atomic check-and-record for replay protection.
 *
 * Must be atomic across the whole enforcement boundary. A per-process store
 * behind more than one replica is theatre: an attacker simply replays against a
 * different replica.
 */
export interface NonceStore {
  /**
   * Record `nonce` and report whether it was previously unseen.
   *
   * `expiresAt` is Unix seconds, after which the entry may be dropped —
   * retention only needs to cover the signature's validity window. Throwing is
   * reported as `nonce_store_unavailable`, never as a replay.
   */
  checkAndRecord(nonce: string, expiresAt: number): Promise<boolean>
}
