import { DEFAULT_PROFILE, isEd25519, jwkThumbprint, type Jwk, type Profile } from '@badge/core'

export class DirectoryPublishError extends Error {
  override readonly name = 'DirectoryPublishError'
}

export interface BuildDirectoryOptions {
  /** Public keys to publish. Order is preserved. */
  readonly keys: readonly Jwk[]
  readonly profile?: Profile
  /** `max-age` for the response. Long enough to be useful, short enough to rotate. */
  readonly cacheMaxAgeSec?: number
  /**
   * Publish keys that are not Ed25519.
   *
   * Off by default: Web Bot Auth verifiers only accept Ed25519 today, so a
   * directory full of RSA keys silently verifies nothing.
   */
  readonly allowNonEd25519?: boolean
}

export interface DirectoryDocument {
  /** Where to serve this from. */
  readonly path: string
  readonly body: string
  readonly headers: Readonly<Record<string, string>>
}

/** JWK members that only ever appear in a *private* key. */
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as const

/**
 * Build the JWKS document for `/.well-known/http-message-signatures-directory`.
 *
 * The `kid` of each published key is set to its RFC 7638 thumbprint. Verifiers
 * must compute that themselves rather than trust it — Badge does — but
 * publishing it makes a directory readable by a human trying to match it
 * against a `keyid` in a log line.
 */
export async function buildDirectory(options: BuildDirectoryOptions): Promise<DirectoryDocument> {
  const profile = options.profile ?? DEFAULT_PROFILE
  const maxAge = options.cacheMaxAgeSec ?? 3600

  const published: Jwk[] = []
  for (const [index, jwk] of options.keys.entries()) {
    assertPublic(jwk, index)
    if (!isEd25519(jwk) && options.allowNonEd25519 !== true) {
      throw new DirectoryPublishError(
        `keys[${index}] is not an Ed25519 key; Web Bot Auth verifiers will ignore it. ` +
          'Pass allowNonEd25519 if that is intended.',
      )
    }
    published.push({ ...jwk, kid: await jwkThumbprint(jwk) })
  }

  return {
    path: profile.directoryPath,
    body: JSON.stringify({ keys: published }),
    headers: {
      'content-type': profile.directoryMediaType,
      'cache-control': `public, max-age=${maxAge}`,
    },
  }
}

/**
 * Refuse to publish anything that looks like a private key.
 *
 * A directory helper is the one place in Badge where a mistake leaks a signing
 * key to the whole internet, so this is a hard error rather than a warning, and
 * it checks for private members by name instead of trusting the caller to have
 * exported the public half.
 */
function assertPublic(jwk: Jwk, index: number): void {
  const record = jwk as unknown as Record<string, unknown>
  for (const member of PRIVATE_MEMBERS) {
    if (record[member] !== undefined) {
      throw new DirectoryPublishError(
        `keys[${index}] contains the private member "${member}". Publish the public key only.`,
      )
    }
  }
  if (typeof jwk.kty !== 'string' || jwk.kty === '') {
    throw new DirectoryPublishError(`keys[${index}] has no "kty"`)
  }
}

/**
 * Check that a rotation set is actually serveable.
 *
 * The rotation the draft describes is: publish the new key, wait a cache TTL,
 * start signing with it, keep the old key until its `exp`. These diagnostics
 * catch the two ways that goes wrong — publishing a key that is already expired,
 * and leaving no overlap between the old and new key.
 */
export function rotationWarnings(keys: readonly Jwk[], now: number): string[] {
  const warnings: string[] = []
  const live = keys.filter(
    (k) => (k.nbf === undefined || k.nbf <= now) && (k.exp === undefined || k.exp > now),
  )
  if (keys.length > 0 && live.length === 0) {
    warnings.push('No published key is valid right now: every key is expired or not yet valid.')
  }
  for (const [index, key] of keys.entries()) {
    if (key.exp !== undefined && key.exp <= now) {
      warnings.push(`keys[${index}] expired at ${key.exp} and can be removed.`)
    }
    if (key.nbf !== undefined && key.exp !== undefined && key.nbf >= key.exp) {
      warnings.push(`keys[${index}] has nbf on or after exp, so it is never valid.`)
    }
  }
  return warnings
}
