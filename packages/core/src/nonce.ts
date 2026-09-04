import type { NonceStore } from './keys.js'
import { systemClock, type Clock } from './types.js'

export interface MemoryNonceStoreOptions {
  /**
   * Cap on remembered nonces.
   *
   * Nonces are attacker-supplied, so an unbounded map is a memory-exhaustion
   * primitive handed to anyone who can send requests.
   */
  readonly maxEntries?: number
  readonly clock?: Clock
}

/**
 * A replay store held in one process.
 *
 * **Correct only behind a single replica.** Two processes do not share this map,
 * so an attacker replays against the other one and the check passes. Behind a
 * load balancer this is theatre; use {@link kvNonceStore} over something
 * shared.
 *
 * When the store is full of live entries it **throws rather than evicting**.
 * Evicting would let an attacker flood the store to push out a target's nonce
 * and then replay it — a bypass that looks like normal operation. Throwing
 * surfaces as `nonce_store_unavailable`, which is `unverifiable`: Badge says it
 * could not complete the check instead of wrongly reporting the request as
 * fresh.
 */
export function memoryNonceStore(options: MemoryNonceStoreOptions = {}): NonceStore {
  const maxEntries = options.maxEntries ?? 100_000
  const clock = options.clock ?? systemClock
  const seen = new Map<string, number>()

  const prune = (now: number): void => {
    for (const [nonce, expiresAt] of seen) {
      if (expiresAt <= now) seen.delete(nonce)
    }
  }

  return {
    async checkAndRecord(nonce, expiresAt) {
      const now = clock.now()
      const existing = seen.get(nonce)
      if (existing !== undefined) {
        if (existing > now) return false
        seen.delete(nonce)
      }

      if (seen.size >= maxEntries) {
        prune(now)
        if (seen.size >= maxEntries) {
          throw new Error(
            `nonce store is full (${maxEntries} live entries); refusing to evict a nonce that ` +
              'could then be replayed',
          )
        }
      }

      seen.set(nonce, expiresAt)
      return true
    },
  }
}

/**
 * The smallest shared store Badge needs: an atomic set-if-absent with a TTL.
 *
 * Deliberately one method. Redis is `SET key 1 NX EX ttl`, Cloudflare's Durable
 * Objects and most KV layers have an equivalent, and nothing else about those
 * systems needs to leak into Badge.
 */
export interface AtomicKeyValueStore {
  /** Set `key` only if it is absent. Returns true when this call set it. */
  setIfAbsent(key: string, ttlSeconds: number): Promise<boolean>
}

export interface KvNonceStoreOptions {
  /** Namespace, so nonces cannot collide with other keys in a shared store. */
  readonly prefix?: string
  readonly clock?: Clock
}

/**
 * Replay protection over a shared store.
 *
 * ```ts
 * const kv = {
 *   setIfAbsent: async (key, ttl) =>
 *     (await redis.set(key, '1', 'EX', ttl, 'NX')) === 'OK',
 * }
 * createVerifier({ keys, replay: kvNonceStore(kv) })
 * ```
 *
 * The atomicity is the store's job and Badge cannot check it. A `setIfAbsent`
 * built from a separate GET and SET has a race that is exactly the replay window
 * this is meant to close.
 */
export function kvNonceStore(
  kv: AtomicKeyValueStore,
  options: KvNonceStoreOptions = {},
): NonceStore {
  const prefix = options.prefix ?? 'badge:nonce:'
  const clock = options.clock ?? systemClock
  return {
    async checkAndRecord(nonce, expiresAt) {
      // Retention only needs to cover the signature's remaining validity: once
      // it expires, a replay fails on the window rather than on the nonce.
      const ttl = Math.max(1, expiresAt - clock.now())
      return await kv.setIfAbsent(`${prefix}${nonce}`, ttl)
    },
  }
}
