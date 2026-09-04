import {
  DEFAULT_PROFILE,
  jwkThumbprint,
  systemClock,
  type CacheResult,
  type Clock,
  type Jwk,
  type KeyResolution,
  type KeyResolver,
  type Profile,
  type ReasonCode,
} from '@badge/core'
import { memoryCache, type DirectoryCache, type DirectoryEntry } from './cache.js'
import { HttpClientError, nodeHttpClient, type HttpClient } from './http.js'

export interface DirectoryResolverOptions {
  readonly http?: HttpClient
  readonly profile?: Profile
  readonly clock?: Clock
  readonly cache?: DirectoryCache
  /** Hard budget for one directory fetch. */
  readonly timeoutMs?: number
  /** Body cap. */
  readonly maxBytes?: number
  /** Cap on keys in one directory. */
  readonly maxKeys?: number
  /** Floor and ceiling applied to the directory's own `Cache-Control: max-age`. */
  readonly minTtlSec?: number
  readonly maxTtlSec?: number
  /** Used when the directory sends no usable `Cache-Control`. */
  readonly defaultTtlSec?: number
  /** How long past freshness an entry may still be served while revalidating. */
  readonly staleWhileRevalidateSec?: number
  /** How long a failure is remembered, so a broken directory is not hammered. */
  readonly negativeTtlSec?: number
  readonly maxOrigins?: number
  /** Cap on distinct origins being fetched at once. */
  readonly maxConcurrentFetches?: number
  /** Consecutive failures before an origin's breaker opens. */
  readonly breakerThreshold?: number
  readonly breakerResetSec?: number
  /**
   * Cap on remembered circuit breakers.
   *
   * Breakers are keyed by the attacker-supplied `Signature-Agent` origin, so an
   * unbounded map is a memory-exhaustion primitive — the same reason the
   * directory cache and the in-flight set are bounded.
   */
  readonly maxBreakers?: number
  /** When set, no other origin is ever fetched. */
  readonly allowedOrigins?: readonly string[]
  /**
   * `strict` requires the media type the draft mandates. `lenient` (the
   * default) also accepts `application/json` and other `+json` types, because
   * plenty of real directories are served by a static file host that has never
   * heard of `application/http-message-signatures-directory+json`, and refusing
   * them turns an interop wart into an outage.
   */
  readonly mediaType?: 'strict' | 'lenient'
}

interface Breaker {
  failures: number
  openUntil: number
}

export function createDirectoryResolver(options: DirectoryResolverOptions = {}): KeyResolver {
  const profile = options.profile ?? DEFAULT_PROFILE
  const clock = options.clock ?? systemClock
  const http = options.http ?? nodeHttpClient()
  const cache = options.cache ?? memoryCache(options.maxOrigins ?? 1024)
  const timeoutMs = options.timeoutMs ?? 1000
  const maxBytes = options.maxBytes ?? 256 * 1024
  const maxKeys = options.maxKeys ?? 100
  const minTtlSec = options.minTtlSec ?? 60
  const maxTtlSec = options.maxTtlSec ?? 3600
  const defaultTtlSec = options.defaultTtlSec ?? 300
  const staleWhileRevalidateSec = options.staleWhileRevalidateSec ?? 86_400
  const negativeTtlSec = options.negativeTtlSec ?? 30
  const maxConcurrentFetches = options.maxConcurrentFetches ?? 32
  const breakerThreshold = options.breakerThreshold ?? 5
  const breakerResetSec = options.breakerResetSec ?? 30
  const maxBreakers = options.maxBreakers ?? 4096
  const mediaType = options.mediaType ?? 'lenient'

  const inFlight = new Map<string, Promise<DirectoryEntry>>()
  const breakers = new Map<string, Breaker>()
  const thumbprints = new WeakMap<Jwk, string>()

  const thumbprintOf = async (jwk: Jwk): Promise<string> => {
    const cached = thumbprints.get(jwk)
    if (cached !== undefined) return cached
    const value = await jwkThumbprint(jwk)
    thumbprints.set(jwk, value)
    return value
  }

  const findKey = async (entry: DirectoryEntry, keyid: string): Promise<Jwk | undefined> => {
    for (const jwk of entry.keys) {
      try {
        if ((await thumbprintOf(jwk)) === keyid) return jwk
      } catch {
        // A key we cannot thumbprint (unknown kty, missing member) simply is
        // not this key. One bad entry must not poison the whole directory.
      }
    }
    return undefined
  }

  const answer = async (
    entry: DirectoryEntry,
    keyid: string,
    cacheResult: CacheResult,
  ): Promise<KeyResolution> => {
    if (entry.failure !== undefined) return { ok: false, reason: entry.failure, cache: cacheResult }
    const jwk = await findKey(entry, keyid)
    return jwk === undefined
      ? { ok: false, reason: 'key_not_found', cache: cacheResult }
      : { ok: true, jwk, cache: cacheResult }
  }

  /**
   * The result of a fetch attempt.
   *
   * `cacheable` is false when the attempt never reached the network — the local
   * concurrency valve refused it. Caching that would blame an origin Badge
   * never contacted, and hold the blame for `negativeTtlSec` afterwards.
   */
  interface FetchOutcome {
    readonly entry: DirectoryEntry
    readonly cacheable: boolean
  }

  /** One fetch per origin at a time, however many requests are waiting on it. */
  const fetchOnce = async (origin: string): Promise<FetchOutcome> => {
    const existing = inFlight.get(origin)
    if (existing !== undefined) return { entry: await existing, cacheable: true }

    if (inFlight.size >= maxConcurrentFetches) {
      // Refusing is better than queueing: an attacker naming thousands of
      // origins would otherwise convert request concurrency into an unbounded
      // outbound fan-out. But this is our backpressure, not the origin's fault,
      // so it is reported to this caller and then forgotten.
      return {
        entry: failureEntry('directory_unreachable', clock.now(), negativeTtlSec),
        cacheable: false,
      }
    }

    const pending = (async () => {
      try {
        const entry = await fetchDirectory(origin)
        breakers.delete(origin)
        return entry
      } catch (err) {
        recordFailure(origin)
        return failureEntry(reasonForTransportError(err), clock.now(), negativeTtlSec)
      } finally {
        inFlight.delete(origin)
      }
    })()
    inFlight.set(origin, pending)
    return { entry: await pending, cacheable: true }
  }

  const recordFailure = (origin: string): void => {
    const breaker = breakers.get(origin) ?? { failures: 0, openUntil: 0 }
    breaker.failures += 1
    if (breaker.failures >= breakerThreshold) {
      breaker.openUntil = clock.now() + breakerResetSec
    }
    breakers.delete(origin)
    breakers.set(origin, breaker)
    if (breakers.size > maxBreakers) pruneBreakers()
  }

  const pruneBreakers = (): void => {
    const now = clock.now()
    for (const [origin, breaker] of breakers) {
      if (breaker.openUntil <= now) breakers.delete(origin)
    }
    // Evicting a breaker only means the origin may be tried again, which is
    // safe. That is why an LRU is acceptable here and not for nonces.
    while (breakers.size > maxBreakers) {
      const oldest = breakers.keys().next()
      if (oldest.done === true) break
      breakers.delete(oldest.value)
    }
  }

  const fetchDirectory = async (origin: string): Promise<DirectoryEntry> => {
    const response = await http.get(`${origin}${profile.directoryPath}`, {
      timeoutMs,
      maxBytes,
      accept: `${profile.directoryMediaType}, application/json;q=0.9`,
    })
    const now = clock.now()

    if (response.status !== 200) {
      throw new HttpClientError(`directory returned HTTP ${response.status}`, 'network')
    }
    if (!mediaTypeAcceptable(response.headers.get('content-type'), profile, mediaType)) {
      return failureEntry('directory_malformed', now, negativeTtlSec)
    }

    let parsed: unknown
    try {
      parsed = JSON.parse(new TextDecoder().decode(response.body)) as unknown
    } catch {
      return failureEntry('directory_malformed', now, negativeTtlSec)
    }
    const keys = keysFrom(parsed)
    if (keys === undefined) return failureEntry('directory_malformed', now, negativeTtlSec)
    if (keys.length > maxKeys) return failureEntry('directory_too_large', now, negativeTtlSec)

    const ttl = clampTtl(response.headers.get('cache-control'))
    return {
      keys,
      freshUntil: now + ttl,
      staleUntil: now + ttl + staleWhileRevalidateSec,
    }
  }

  /**
   * The directory's `Cache-Control` is advisory, and always clamped into
   * `[minTtlSec, maxTtlSec]`.
   *
   * The floor is the important half: without it an origin could send
   * `max-age=0` or `no-store` and make Badge fetch its directory on every
   * single request, which is an amplification hazard pointed at us by someone
   * else's configuration. So `no-store` and `no-cache` are honoured as far as
   * the floor allows — the shortest lifetime Badge will use, rather than the
   * default — and no further.
   */
  const clampTtl = (cacheControl: string | undefined): number => {
    const maxAge = parseMaxAge(cacheControl)
    if (maxAge === undefined) return defaultTtlSec
    return Math.min(maxTtlSec, Math.max(minTtlSec, maxAge))
  }

  return {
    async resolve({ origin, keyid }): Promise<KeyResolution> {
      if (origin === undefined) return { ok: false, reason: 'key_not_found' }
      if (options.allowedOrigins !== undefined && !options.allowedOrigins.includes(origin)) {
        return { ok: false, reason: 'signature_agent_not_allowed' }
      }

      const now = clock.now()
      const cached = await cache.get(origin)
      if (cached !== undefined && now < cached.freshUntil) {
        return await answer(cached, keyid, 'hit')
      }

      const breaker = breakers.get(origin)
      const breakerOpen = breaker !== undefined && now < breaker.openUntil

      if (cached !== undefined && now < cached.staleUntil) {
        // Serve what we have and refresh behind the request. The alternative is
        // a synchronous fetch on a live request path, which is the thing this
        // whole cache exists to avoid.
        if (!breakerOpen) {
          void fetchOnce(origin)
            .then(async (outcome) => {
              // Never overwrite a usable stale entry with a failure. The stale
              // window exists precisely to keep serving while the origin is
              // unwell; replacing good keys with a 30-second negative entry
              // would throw away the remaining hours of it and hand every
              // caller of that origin an `unverifiable` verdict.
              if (outcome.cacheable && outcome.entry.failure === undefined) {
                await cache.set(origin, outcome.entry)
              }
            })
            .catch(() => undefined)
        }
        return await answer(cached, keyid, 'stale')
      }

      if (breakerOpen) {
        // Open breaker: fail without opening a socket.
        return { ok: false, reason: 'directory_unreachable', cache: 'miss' }
      }

      const outcome = await fetchOnce(origin)
      if (outcome.cacheable) await cache.set(origin, outcome.entry)
      return await answer(outcome.entry, keyid, 'miss')
    },
  }
}

function failureEntry(failure: ReasonCode, now: number, negativeTtlSec: number): DirectoryEntry {
  return {
    keys: [],
    failure,
    freshUntil: now + negativeTtlSec,
    // A cached failure is never served stale: once it lapses we try again.
    staleUntil: now + negativeTtlSec,
  }
}

function reasonForTransportError(err: unknown): ReasonCode {
  if (!(err instanceof HttpClientError)) return 'directory_unreachable'
  switch (err.kind) {
    case 'timeout':
      return 'directory_timeout'
    case 'too-large':
      return 'directory_too_large'
    case 'blocked':
    case 'network':
      return 'directory_unreachable'
  }
}

function keysFrom(parsed: unknown): readonly Jwk[] | undefined {
  if (typeof parsed !== 'object' || parsed === null) return undefined
  const keys = (parsed as { keys?: unknown }).keys
  if (!Array.isArray(keys)) return undefined
  if (keys.some((k) => typeof k !== 'object' || k === null || Array.isArray(k))) return undefined
  return keys as readonly Jwk[]
}

function mediaTypeAcceptable(
  contentType: string | undefined,
  profile: Profile,
  mode: 'strict' | 'lenient',
): boolean {
  if (contentType === undefined) return mode === 'lenient'
  const essence = (contentType.split(';')[0] ?? '').trim().toLowerCase()
  if (essence === profile.directoryMediaType) return true
  if (mode === 'strict') return false
  return essence === 'application/json' || essence.endsWith('+json')
}

function parseMaxAge(cacheControl: string | undefined): number | undefined {
  if (cacheControl === undefined) return undefined
  // Zero rather than undefined: the caller clamps it to the floor, so a
  // directory asking not to be cached gets the shortest lifetime Badge offers
  // instead of the default one. See clampTtl for why it is not honoured
  // literally.
  if (/(^|,)\s*(no-store|no-cache)\s*(,|$)/i.test(cacheControl)) return 0
  const match = /(?:^|,)\s*max-age\s*=\s*"?(\d+)"?/i.exec(cacheControl)
  if (match?.[1] === undefined) return undefined
  return Number(match[1])
}
