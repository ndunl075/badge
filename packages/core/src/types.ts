import type { FailureClass, ReasonCode, Status } from './reasons.js'

/**
 * A request, stripped of framework specifics.
 *
 * Adapters build these; nothing above this layer knows what an Express `req` is.
 * Keeping it an interface (rather than a concrete object) lets adapters read
 * lazily from the native request instead of copying every header.
 */
export interface NormalizedRequest {
  readonly method: string
  readonly scheme: 'http' | 'https'
  /**
   * `host[:port]` as the *client* addressed it.
   *
   * This is the single most common source of false `signature_invalid`
   * verdicts: the signer signed the authority it dialled, so if a load balancer
   * rewrites `Host`, every signature fails and the failure looks cryptographic.
   * Adapters take an explicit authority strategy; Badge records the resolved
   * value in the decision so this is a five-second diagnosis.
   */
  readonly authority: string
  /** Raw, not percent-decoded. */
  readonly path: string
  /** Raw, without the leading `?`. */
  readonly query: string
  /**
   * Field value as received — trimmed, obs-folds joined, repeated fields
   * comma-joined per RFC 9421 §2.1. Never re-serialized from a parse tree:
   * round-tripping a structured field changes bytes and breaks the signature
   * base.
   */
  header(name: string): string | undefined
}

/** The subset of a request that policy is allowed to match on. */
export interface RequestFacts {
  readonly method: string
  readonly path: string
  readonly authority: string
}

export interface VerdictTiming {
  /** Wall time spent inside the verifier, microseconds. */
  readonly totalUs: number
  /** Wall time spent resolving a key, microseconds. Absent if no lookup ran. */
  readonly directoryUs?: number
  /** Which cache tier answered the directory lookup. Absent if no lookup ran. */
  readonly cache?: 'hit' | 'stale' | 'miss'
}

/**
 * The verifier's answer. Always carries a reason, including on success.
 *
 * `status` is the headline. `class` is what policy should actually be built on
 * — see {@link FailureClass}.
 */
export interface Verdict {
  readonly status: Status
  readonly class: FailureClass
  readonly reason: ReasonCode
  /** Which draft revision's rules judged this request, e.g. `wba-2026-03`. */
  readonly profile: string
  /** Normalized `https` origin from `Signature-Agent`, if it parsed. */
  readonly signatureAgent?: string
  /** The `keyid` the caller presented — an RFC 7638 thumbprint. */
  readonly keyid?: string
  /** Which signature label in `Signature-Input` was selected. */
  readonly label?: string
  readonly created?: number
  readonly expires?: number
  readonly covered?: readonly string[]
  readonly timing: VerdictTiming
}

export type Action = 'allow' | 'deny' | 'log-only'

/** A policy outcome. `ruleId` is never empty — the implicit default is `"default"`. */
export interface Decision {
  readonly action: Action
  readonly ruleId: string
  readonly verdict: Verdict
  /** Operator label matched from `signatureAgent`, if the policy defined one. */
  readonly operator?: string
}

/** Injected so tests can move time without touching the system clock. */
export interface Clock {
  /** Unix seconds. */
  now(): number
}

export const systemClock: Clock = {
  now: () => Math.floor(Date.now() / 1000),
}
