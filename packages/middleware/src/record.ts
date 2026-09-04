import type { Decision, RequestFacts } from '@badge/core'

/**
 * One structured record per decision.
 *
 * The field list is the privacy boundary, enforced by construction rather than
 * by a redaction pass: there is nowhere to put a signature, a header, or a
 * body, so none can be logged by accident. `keyid` and the signature agent
 * origin identify a caller adequately and are already public information.
 */
export interface DecisionRecord {
  readonly ts: string
  readonly status: string
  readonly class: string
  readonly reason: string
  readonly action: string
  readonly rule: string
  readonly profile: string
  readonly route: string
  readonly authority: string
  readonly signature_agent?: string
  readonly keyid?: string
  readonly operator?: string
  readonly cache?: string
  readonly total_us: number
  readonly directory_us?: number
  /** Present only in dry-run mode: what the policy would have done. */
  readonly would_action?: string
}

export function toRecord(
  decision: Decision,
  facts: RequestFacts,
  now: Date,
  wouldAction?: string,
): DecisionRecord {
  const { verdict } = decision
  return {
    ts: now.toISOString(),
    status: verdict.status,
    class: verdict.class,
    reason: verdict.reason,
    action: decision.action,
    rule: decision.ruleId,
    profile: verdict.profile,
    route: `${facts.method} ${facts.path}`,
    authority: facts.authority,
    ...(verdict.signatureAgent === undefined ? {} : { signature_agent: verdict.signatureAgent }),
    ...(verdict.keyid === undefined ? {} : { keyid: verdict.keyid }),
    ...(decision.operator === undefined ? {} : { operator: decision.operator }),
    ...(verdict.timing.cache === undefined ? {} : { cache: verdict.timing.cache }),
    total_us: verdict.timing.totalUs,
    ...(verdict.timing.directoryUs === undefined
      ? {}
      : { directory_us: verdict.timing.directoryUs }),
    ...(wouldAction === undefined ? {} : { would_action: wouldAction }),
  }
}
