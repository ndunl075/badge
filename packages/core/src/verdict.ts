import { reasonInfo, type ReasonCode } from './reasons.js'
import type { Verdict, VerdictTiming } from './types.js'

/** Everything about a verdict that is not implied by its reason code. */
export interface VerdictDetails {
  readonly profile: string
  readonly signatureAgent?: string | undefined
  readonly keyid?: string | undefined
  readonly label?: string | undefined
  readonly created?: number | undefined
  readonly expires?: number | undefined
  readonly covered?: readonly string[] | undefined
  readonly timing?: VerdictTiming | undefined
}

/**
 * The only way to build a {@link Verdict}.
 *
 * `status` and `class` are derived from the reason code rather than passed in,
 * which makes the "a verdict always has a reason" invariant unbreakable by
 * construction instead of by review.
 */
export function verdictFor(reason: ReasonCode, details: VerdictDetails): Verdict {
  const info = reasonInfo(reason)
  const verdict: {
    -readonly [K in keyof Verdict]: Verdict[K]
  } = {
    status: info.status,
    class: info.class,
    reason,
    profile: details.profile,
    timing: details.timing ?? { totalUs: 0 },
  }
  if (details.signatureAgent !== undefined) verdict.signatureAgent = details.signatureAgent
  if (details.keyid !== undefined) verdict.keyid = details.keyid
  if (details.label !== undefined) verdict.label = details.label
  if (details.created !== undefined) verdict.created = details.created
  if (details.expires !== undefined) verdict.expires = details.expires
  if (details.covered !== undefined) verdict.covered = details.covered
  return verdict
}
