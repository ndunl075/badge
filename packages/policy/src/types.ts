import type { Action, FailureClass, ReasonCode, Status } from '@badge/core'

/**
 * A policy is data, never code.
 *
 * There is no expression language and nothing is ever evaluated, so a policy
 * can be reviewed, diffed, and linted in CI like any other configuration. The
 * cost is that some rules cannot be expressed; that is the intended trade.
 */
export interface Policy {
  readonly version: 1
  /**
   * Applied when no rule matches.
   *
   * The template ships as `log-only` so installing Badge cannot break a live
   * site. Changing it is a deliberate, reviewable edit.
   */
  readonly default: Action
  /** Human-readable labels over `Signature-Agent` origins. Operator-authored; Badge ships none. */
  readonly operators?: Readonly<Record<string, readonly string[]>>
  /** Evaluated in order. First match wins. */
  readonly rules?: readonly Rule[]
}

export interface Rule {
  /** Reported in every decision this rule produces, so a log line names its cause. */
  readonly id: string
  readonly action: Action
  readonly when?: Condition
  /**
   * Route patterns, e.g. `GET /docs/**`, `GET|HEAD /api/*`, or `/checkout/**`
   * for any method. A rule with no routes matches every route.
   */
  readonly routes?: readonly string[]
}

/**
 * Fields are ANDed; the values within one field are ORed.
 *
 * `class` is usually the right field to match on. `status` alone cannot tell a
 * forged signature from a directory timeout — see ARCHITECTURE.md §8.1.
 */
export interface Condition {
  readonly status?: Status | readonly Status[]
  readonly class?: FailureClass | readonly FailureClass[]
  readonly reason?: ReasonCode | readonly ReasonCode[]
  /** Operator label, resolved from the policy's `operators` map. */
  readonly operator?: string | readonly string[]
  /** Raw `Signature-Agent` origin, for one-off rules with no label. */
  readonly origin?: string | readonly string[]
}

export class PolicyError extends Error {
  override readonly name = 'PolicyError'
  constructor(
    message: string,
    /** Where in the document the problem is, e.g. `rules[2].action`. */
    readonly path: string,
  ) {
    super(`${message} (at ${path})`)
  }
}
