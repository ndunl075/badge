import type { Jwk, ReasonCode } from '@badge/core'

/**
 * What a cache holds for one origin.
 *
 * Deliberately JSON-serializable so the same shape works for the in-process LRU
 * and a shared store like Redis, letting a fleet warm once rather than once per
 * process.
 */
export interface DirectoryEntry {
  /** Keys as published. Empty when this entry records a failure. */
  readonly keys: readonly Jwk[]
  /** A cached failure, so a broken directory is not re-fetched on every request. */
  readonly failure?: ReasonCode
  /** Unix seconds until which the entry may be served without revalidating. */
  readonly freshUntil: number
  /** Unix seconds until which the entry may be served *while* revalidating. */
  readonly staleUntil: number
}

export interface DirectoryCache {
  get(origin: string): Promise<DirectoryEntry | undefined>
  set(origin: string, entry: DirectoryEntry): Promise<void>
}

/**
 * A bounded in-process cache.
 *
 * The bound is the point: origins come from attacker-controlled input, so an
 * unbounded map is a memory-exhaustion primitive handed to anyone who can send
 * requests.
 */
export function memoryCache(maxOrigins = 1024): DirectoryCache {
  const entries = new Map<string, DirectoryEntry>()
  return {
    async get(origin) {
      const entry = entries.get(origin)
      if (entry === undefined) return undefined
      // Refresh recency.
      entries.delete(origin)
      entries.set(origin, entry)
      return entry
    },
    async set(origin, entry) {
      entries.delete(origin)
      entries.set(origin, entry)
      while (entries.size > maxOrigins) {
        const oldest = entries.keys().next()
        if (oldest.done === true) break
        entries.delete(oldest.value)
      }
    },
  }
}
