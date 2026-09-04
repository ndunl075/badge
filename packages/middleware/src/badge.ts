import {
  createVerifier,
  systemClock,
  type Clock,
  type Decision,
  type KeyResolver,
  type NormalizedRequest,
  type Profile,
  type RequestFacts,
  type Verifier,
} from '@badge/core'
import { createDirectoryResolver } from '@badge/directory'
import { DEFAULT_POLICY, compilePolicy, parsePolicy, type Policy } from '@badge/policy'
import { toRecord } from './record.js'
import { compositeSink, jsonSink, type Sink } from './sink.js'

export interface BadgeOptions {
  /** Defaults to the observe-only policy, so installing Badge cannot break a site. */
  readonly policy?: Policy
  /** Defaults to a directory resolver with the standard guards and caches. */
  readonly keys?: KeyResolver
  readonly verifier?: Verifier
  readonly profile?: Profile
  readonly clock?: Clock
  /** Defaults to a JSON-lines sink on stdout with `unknown` verdicts sampled. */
  readonly sinks?: readonly Sink[]
  /**
   * Evaluate the policy fully, report what it *would* have done, and act
   * `log-only` regardless.
   *
   * This is how an operator earns the confidence to enforce: run it against
   * real traffic, read the `would_action` field, and only then turn it off.
   */
  readonly dryRun?: boolean
  readonly clockSkewSec?: number
  readonly maxAgeSec?: number
}

export interface Badge {
  /** Verify, apply the policy, record the decision. */
  inspect(request: NormalizedRequest, facts?: RequestFacts): Promise<Decision>
}

export function createBadge(options: BadgeOptions = {}): Badge {
  const profile = options.profile
  const clock = options.clock ?? systemClock
  const verifier =
    options.verifier ??
    createVerifier({
      keys:
        options.keys ??
        createDirectoryResolver({ ...(profile === undefined ? {} : { profile }), clock }),
      clock,
      ...(profile === undefined ? {} : { profile }),
      ...(options.clockSkewSec === undefined ? {} : { clockSkewSec: options.clockSkewSec }),
      ...(options.maxAgeSec === undefined ? {} : { maxAgeSec: options.maxAgeSec }),
    })
  const compiled = compilePolicy(parsePolicy(options.policy ?? DEFAULT_POLICY))
  const sink = compositeSink(...(options.sinks ?? [jsonSink()]))
  const dryRun = options.dryRun === true

  return {
    async inspect(request, facts): Promise<Decision> {
      const requestFacts: RequestFacts = facts ?? {
        method: request.method,
        path: request.path,
        authority: request.authority,
      }
      const verdict = await verifier.verify(request)
      const decided = compiled.evaluate(verdict, requestFacts)

      const effective: Decision = dryRun ? { ...decided, action: 'log-only' } : decided
      sink.record(
        toRecord(
          effective,
          requestFacts,
          new Date(clock.now() * 1000),
          dryRun ? decided.action : undefined,
        ),
      )
      return effective
    },
  }
}
