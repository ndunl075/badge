import { SignatureBaseError, buildSignatureBase, type StructuredFieldType } from './base.js'
import { importEd25519PublicKey, isEd25519, keyValidityAt, type Jwk } from './crypto.js'
import { verifyEd25519 } from './crypto.js'
import type { CacheResult, KeyResolver, NonceStore } from './keys.js'
import { DEFAULT_PROFILE, type Profile } from './profile.js'
import type { ReasonCode } from './reasons.js'
import { parseDictionary, parseItem } from './sfv/parse.js'
import type { BareItem, Dictionary, Item } from './sfv/types.js'
import { systemClock, type Clock, type NormalizedRequest, type Verdict } from './types.js'
import { verdictFor, type VerdictDetails } from './verdict.js'

export interface VerifierOptions {
  /** How a `keyid` becomes a public key. The only step permitted to do I/O. */
  readonly keys: KeyResolver
  /** Which draft revision's rules to apply. Recorded in every verdict. */
  readonly profile?: Profile
  readonly clock?: Clock
  /** How far into the future `created` may be, in seconds. */
  readonly clockSkewSec?: number
  /** Ceiling on `now - created`, regardless of what `expires` says. */
  readonly maxAgeSec?: number
  /**
   * When set, only these `Signature-Agent` origins are accepted.
   *
   * The strongest available answer to attacker-driven egress: nothing outside
   * this list is ever fetched.
   */
  readonly allowedOrigins?: readonly string[]
  /** Opt-in replay protection. Off by default — see ARCHITECTURE.md §8.4. */
  readonly replay?: NonceStore
  /**
   * Smallest nonce Badge will accept, in decoded bytes, when replay protection
   * is on.
   *
   * The reference implementation generates and requires exactly 64. Badge's
   * default is lower so a signer using a shorter but still unguessable nonce
   * interoperates, and high enough that the space cannot be enumerated and
   * pre-seeded into the replay store — which would turn replay protection into
   * a denial of service against the signer it is meant to protect. Set it to 64
   * to match the reference exactly.
   */
  readonly minNonceBytes?: number
  /**
   * Additions to the structured field type map, so `;sf` and `;key` can
   * canonicalize fields Badge does not know about.
   */
  readonly structuredFieldTypes?: Readonly<Record<string, StructuredFieldType>>
}

export interface Verifier {
  verify(request: NormalizedRequest): Promise<Verdict>
}

/** Accumulated as the pipeline learns things, so every exit reports what it knew. */
interface Facts {
  profile: string
  signatureAgent?: string
  keyid?: string
  label?: string
  created?: number
  expires?: number
  covered?: readonly string[]
  directoryUs?: number
  cache?: CacheResult
}

export function createVerifier(options: VerifierOptions): Verifier {
  const profile = options.profile ?? DEFAULT_PROFILE
  const clock = options.clock ?? systemClock
  const clockSkewSec = options.clockSkewSec ?? 5
  const maxAgeSec = options.maxAgeSec ?? 300
  const minNonceBytes = options.minNonceBytes ?? 16
  const allowedOrigins = options.allowedOrigins

  return {
    async verify(request: NormalizedRequest): Promise<Verdict> {
      const startedAt = performance.now()
      const facts: Facts = { profile: profile.id }
      const done = (reason: ReasonCode): Verdict =>
        verdictFor(reason, toDetails(facts, performance.now() - startedAt))

      try {
        // Step 1: the cheap presence test. Almost all production traffic exits
        // here, before any parsing, allocation, or I/O.
        const rawInput = request.header('signature-input')
        const rawAgent = request.header('signature-agent')
        if (rawInput === undefined) {
          return done(rawAgent === undefined ? 'no_signature_fields' : 'signature_input_malformed')
        }

        // Step 2: parse.
        let inputs: Dictionary
        try {
          inputs = parseDictionary(rawInput)
        } catch {
          return done('signature_input_malformed')
        }

        const rawSignature = request.header('signature')
        if (rawSignature === undefined) return done('signature_malformed')
        let signatures: Dictionary
        try {
          signatures = parseDictionary(rawSignature)
        } catch {
          return done('signature_malformed')
        }

        // Step 3: select the Web Bot Auth signature. Other signatures on the
        // message are ignored rather than treated as errors.
        const selected = selectWebBotAuth(inputs, profile.tag)
        if (selected === undefined) return done('no_web_bot_auth_tag')
        const { label, components, params, source } = selected
        facts.label = label
        facts.covered = components.map((c) => (c.value.type === 'string' ? c.value.value : '?'))

        // Step 4: preflight, cheapest and most attributable checks first.
        const keyid = stringParam(params, 'keyid')
        if (keyid === undefined) {
          if (profile.requireKeyid) return done('missing_keyid')
        } else {
          facts.keyid = keyid
        }

        const alg = stringParam(params, 'alg')
        if (alg !== undefined && !profile.algorithms.includes(alg)) {
          return done('unsupported_algorithm')
        }

        const created = integerParam(params, 'created')
        if (created === undefined) {
          if (profile.requireCreated) return done('missing_created')
        } else {
          facts.created = created
        }
        const expires = integerParam(params, 'expires')
        if (expires === undefined) {
          if (profile.requireExpires) return done('missing_expires')
        } else {
          facts.expires = expires
        }

        const missingComponent = checkCoveredComponents(components, request, profile)
        if (missingComponent !== undefined) return done(missingComponent)

        // Step 5: identity of the directory.
        let origin: string | undefined
        if (rawAgent !== undefined) {
          const parsed = parseSignatureAgent(rawAgent)
          if (parsed === undefined) return done('signature_agent_malformed')
          origin = parsed
          facts.signatureAgent = parsed
        } else if (profile.requireSignatureAgent) {
          return done('signature_agent_missing')
        }
        if (
          allowedOrigins !== undefined &&
          (origin === undefined || !allowedOrigins.includes(origin))
        ) {
          return done('signature_agent_not_allowed')
        }

        // Step 6: the window. Structural problems are reported before expiry so
        // a nonsense window reads as malformed rather than merely stale.
        const now = clock.now()
        if (created !== undefined && expires !== undefined) {
          if (expires - created > profile.maxWindowSec) return done('validity_window_too_long')
          if (expires < created) return done('validity_window_too_long')
        }
        if (created !== undefined && created > now + clockSkewSec) return done('created_in_future')
        if (expires !== undefined && now - clockSkewSec > expires) return done('signature_expired')
        if (created !== undefined && now - created > maxAgeSec) return done('signature_too_old')

        // Step 7: the signature bytes.
        const signatureBytes = signatureFor(signatures, label)
        if (signatureBytes === undefined) return done('signature_malformed')

        // Step 8: reconstruct the base.
        let base: string
        try {
          base = buildSignatureBase({
            request,
            components,
            signatureParamsSource: source,
            ...(options.structuredFieldTypes === undefined
              ? {}
              : { structuredFieldTypes: options.structuredFieldTypes }),
          })
        } catch (err) {
          if (err instanceof SignatureBaseError) return done(err.reason)
          throw err
        }

        // Step 9: resolve the key. The only I/O in the pipeline.
        if (keyid === undefined) return done('missing_keyid')
        const directoryStartedAt = performance.now()
        const resolution = await options.keys.resolve({ origin, keyid, now })
        facts.directoryUs = performance.now() - directoryStartedAt
        if (resolution.cache !== undefined) facts.cache = resolution.cache
        if (!resolution.ok) return done(resolution.reason)

        const jwk: Jwk = resolution.jwk
        if (!isEd25519(jwk)) return done('unsupported_algorithm')
        switch (keyValidityAt(jwk, now)) {
          case 'not-yet-valid':
            return done('key_not_yet_valid')
          case 'expired':
            return done('key_expired')
          case 'valid':
            break
        }

        // Step 10: verify.
        const publicKey = await importEd25519PublicKey(jwk)
        const verified = await verifyEd25519(
          publicKey,
          signatureBytes,
          new TextEncoder().encode(base),
        )
        if (!verified) return done('signature_invalid')

        // Step 11: replay, only when a store is configured.
        if (options.replay !== undefined) {
          const nonce = stringParam(params, 'nonce')
          if (nonce === undefined) return done('nonce_missing')
          if (decodedNonceBytes(nonce) < minNonceBytes) return done('nonce_invalid')
          let fresh: boolean
          try {
            fresh = await options.replay.checkAndRecord(
              nonce,
              replayRetainUntil(created, expires, clockSkewSec, maxAgeSec, now),
            )
          } catch {
            // A store outage must never read as a replay: that would deny
            // legitimate traffic the moment Redis hiccups.
            return done('nonce_store_unavailable')
          }
          if (!fresh) return done('replay_detected')
        }

        return done('ok')
      } catch {
        return done('internal_error')
      }
    },
  }
}

/**
 * The last instant this signature could still be accepted.
 *
 * A nonce must be remembered for exactly that long. Remembering it only until
 * `expires` leaves the signature replayable for the final `clockSkewSec`
 * seconds of its own acceptance window, because the expiry check allows
 * `now - clockSkewSec <= expires` — a hole that grows with any skew allowance
 * an operator raises.
 *
 * Acceptance needs both the expiry and the age check to hold, so the earlier of
 * the two bounds is the real deadline, and retaining past it would only waste
 * space in the store.
 */
function replayRetainUntil(
  created: number | undefined,
  expires: number | undefined,
  clockSkewSec: number,
  maxAgeSec: number,
  now: number,
): number {
  const byExpiry = (expires ?? now) + clockSkewSec
  if (created === undefined) return byExpiry
  return Math.min(byExpiry, created + maxAgeSec)
}

interface Selection {
  readonly label: string
  readonly components: readonly Item[]
  readonly params: ReadonlyMap<string, BareItem>
  readonly source: string
}

/**
 * Pick the first signature tagged for Web Bot Auth.
 *
 * The tag must be a String. A Token spelling `web-bot-auth` is a different
 * value in RFC 9651 and must not be accepted as one.
 */
function selectWebBotAuth(inputs: Dictionary, tag: string): Selection | undefined {
  for (const [label, entry] of inputs) {
    if (entry.value.kind !== 'inner-list') continue
    const tagParam = entry.value.params.get('tag')
    if (tagParam?.type !== 'string' || tagParam.value !== tag) continue
    return {
      label,
      components: entry.value.items,
      params: entry.value.params,
      source: entry.source,
    }
  }
  return undefined
}

function checkCoveredComponents(
  components: readonly Item[],
  request: NormalizedRequest,
  profile: Profile,
): ReasonCode | undefined {
  const names = new Set<string>()
  for (const component of components) {
    if (component.value.type !== 'string') return 'signature_input_malformed'
    names.add(component.value.value)
  }
  // Each group is satisfied by any one of its members, so a signature over
  // `@target-uri` satisfies the `@authority` requirement it subsumes.
  for (const group of profile.requiredComponents) {
    if (!group.some((name) => names.has(name))) return 'covered_components_insufficient'
  }
  for (const required of profile.requiredComponentsWhenPresent) {
    if (request.header(required) !== undefined && !names.has(required)) {
      return 'covered_components_insufficient'
    }
  }
  return undefined
}

/**
 * `Signature-Agent` is a structured field String holding an absolute `https:`
 * URI. Anything else — a bare token, an `http:` URI, a path — is malformed.
 */
function parseSignatureAgent(raw: string): string | undefined {
  let item: Item
  try {
    item = parseItem(raw)
  } catch {
    return undefined
  }
  if (item.value.type !== 'string') return undefined
  let url: URL
  try {
    url = new URL(item.value.value)
  } catch {
    return undefined
  }
  if (url.protocol !== 'https:') return undefined
  return url.origin
}

function signatureFor(signatures: Dictionary, label: string): Uint8Array | undefined {
  const entry = signatures.get(label)
  if (entry?.value.kind !== 'item') return undefined
  if (entry.value.value.type !== 'binary') return undefined
  return entry.value.value.value
}

/**
 * Decoded length of a base64 or base64url nonce, or 0 if it is not either.
 *
 * Computed from the encoded length rather than by decoding: the value is
 * attacker-controlled and there is no reason to allocate a buffer for it.
 */
function decodedNonceBytes(nonce: string): number {
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(nonce)) return 0
  const unpadded = nonce.replace(/=+$/, '').length
  return Math.floor((unpadded * 3) / 4)
}

function stringParam(params: ReadonlyMap<string, BareItem>, name: string): string | undefined {
  const value = params.get(name)
  return value?.type === 'string' ? value.value : undefined
}

function integerParam(params: ReadonlyMap<string, BareItem>, name: string): number | undefined {
  const value = params.get(name)
  return value?.type === 'integer' ? value.value : undefined
}

function toDetails(facts: Facts, elapsedMs: number): VerdictDetails {
  return {
    profile: facts.profile,
    signatureAgent: facts.signatureAgent,
    keyid: facts.keyid,
    label: facts.label,
    created: facts.created,
    expires: facts.expires,
    covered: facts.covered,
    timing: {
      totalUs: Math.round(elapsedMs * 1000),
      ...(facts.directoryUs === undefined
        ? {}
        : { directoryUs: Math.round(facts.directoryUs * 1000) }),
      ...(facts.cache === undefined ? {} : { cache: facts.cache }),
    },
  }
}
