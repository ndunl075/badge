/**
 * Reason codes are public API.
 *
 * Two rules govern this file, both load-bearing for the rest of Badge:
 *
 * 1. A verdict always has a reason. There is no success-shaped return with an
 *    empty explanation, and no failure that surfaces as `null`.
 * 2. Codes are added, never repurposed. A log line written a year ago must still
 *    mean what it meant then.
 *
 * See ARCHITECTURE.md §8.2.
 */

/** The headline verdict. Never enough to act on by itself — see {@link FailureClass}. */
export type Status = 'verified' | 'claimed' | 'unknown'

/**
 * What kind of outcome this was, and crucially *whose fault it was*.
 *
 * `untrusted` means the caller failed a check it controls: assume hostile.
 * `unverifiable` means **Badge** could not complete the check — a directory
 * timeout, a broken cache, an internal error. Denying on `unverifiable` wires a
 * site's availability to its own egress, so policy must be able to tell the two
 * apart. That is the entire reason this axis exists separately from `status`.
 */
export type FailureClass = 'ok' | 'absent' | 'malformed' | 'expired' | 'untrusted' | 'unverifiable'

export const REASONS = {
  /** Signature verified against a key published at the named origin. */
  ok: { status: 'verified', class: 'ok' },

  // -- absent: the caller made no claim at all ------------------------------
  /** Neither `Signature-Input` nor `Signature-Agent` was present. */
  no_signature_fields: { status: 'unknown', class: 'absent' },
  /** Signatures were present, but none carried `tag="web-bot-auth"`. */
  no_web_bot_auth_tag: { status: 'unknown', class: 'absent' },

  // -- malformed: the caller made a claim it got wrong ----------------------
  signature_input_malformed: { status: 'claimed', class: 'malformed' },
  signature_malformed: { status: 'claimed', class: 'malformed' },
  /** `Signature-Agent` was not a quoted, absolute `https:` URI. */
  signature_agent_malformed: { status: 'claimed', class: 'malformed' },
  /** The profile needs `Signature-Agent` to find a key, and it was absent. */
  signature_agent_missing: { status: 'claimed', class: 'malformed' },
  /** Covered components omitted `@authority`, or `signature-agent` when present. */
  covered_components_insufficient: { status: 'claimed', class: 'malformed' },
  unsupported_algorithm: { status: 'claimed', class: 'malformed' },
  missing_keyid: { status: 'claimed', class: 'malformed' },
  missing_created: { status: 'claimed', class: 'malformed' },
  /** A signature with no `expires` is a permanent bearer token. */
  missing_expires: { status: 'claimed', class: 'malformed' },
  validity_window_too_long: { status: 'claimed', class: 'malformed' },
  /** Replay protection is on and the signature carried no `nonce`. */
  nonce_missing: { status: 'claimed', class: 'malformed' },

  // -- expired: a real claim, outside its window ----------------------------
  created_in_future: { status: 'claimed', class: 'expired' },
  signature_expired: { status: 'claimed', class: 'expired' },
  /** Within `expires`, but older than the verifier's own `maxAgeSec` ceiling. */
  signature_too_old: { status: 'claimed', class: 'expired' },

  // -- untrusted: assume hostile --------------------------------------------
  /** No JWK in the directory had a thumbprint matching `keyid`. */
  key_not_found: { status: 'claimed', class: 'untrusted' },
  key_not_yet_valid: { status: 'claimed', class: 'untrusted' },
  key_expired: { status: 'claimed', class: 'untrusted' },
  signature_invalid: { status: 'claimed', class: 'untrusted' },
  replay_detected: { status: 'claimed', class: 'untrusted' },
  /** `allowedOrigins` is configured and this origin is not in it. */
  signature_agent_not_allowed: { status: 'claimed', class: 'untrusted' },

  // -- unverifiable: our problem, never the caller's ------------------------
  directory_unreachable: { status: 'claimed', class: 'unverifiable' },
  directory_timeout: { status: 'claimed', class: 'unverifiable' },
  /**
   * A broken directory is far more often an operator's deploy bug than an
   * attack, and the safe reading of ambiguity is "we could not check".
   */
  directory_malformed: { status: 'claimed', class: 'unverifiable' },
  directory_too_large: { status: 'claimed', class: 'unverifiable' },
  /** The nonce store was unreachable, so replay could not be ruled out. */
  nonce_store_unavailable: { status: 'claimed', class: 'unverifiable' },
  internal_error: { status: 'claimed', class: 'unverifiable' },
} as const satisfies Record<string, { status: Status; class: FailureClass }>

export type ReasonCode = keyof typeof REASONS

/** Every reason code, for exhaustiveness checks and documentation generation. */
export const REASON_CODES = Object.keys(REASONS) as ReasonCode[]

/** The `status` and `class` a reason code implies. This mapping is fixed. */
export function reasonInfo(reason: ReasonCode): { status: Status; class: FailureClass } {
  return REASONS[reason]
}

/**
 * True when the reason means *Badge* failed, not the caller.
 *
 * Policy that denies on these trades the site's availability for the verifier's
 * uptime. `badge policy lint` warns about it for that reason.
 */
export function isOurFault(reason: ReasonCode): boolean {
  return REASONS[reason].class === 'unverifiable'
}
