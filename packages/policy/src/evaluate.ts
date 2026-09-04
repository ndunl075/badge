import type { Decision, RequestFacts, Verdict } from '@badge/core'
import { compileRoute, matchesRoute, type RoutePattern } from './route.js'
import type { Condition, Policy, Rule } from './types.js'

/**
 * A policy with its routes compiled once.
 *
 * Compiling globs per request would put a regex build on the hot path of every
 * request the server handles, signed or not.
 */
export interface CompiledPolicy {
  readonly policy: Policy
  evaluate(verdict: Verdict, facts: RequestFacts): Decision
}

interface CompiledRule {
  readonly rule: Rule
  readonly routes?: readonly RoutePattern[]
}

export function compilePolicy(policy: Policy): CompiledPolicy {
  const rules: CompiledRule[] = (policy.rules ?? []).map((rule, index) => ({
    rule,
    ...(rule.routes === undefined
      ? {}
      : { routes: rule.routes.map((r) => compileRoute(r, `rules[${index}].routes`)) }),
  }))

  // origin -> operator label, built once. Later entries do not override earlier
  // ones, so an origin listed under two operators keeps the first label and
  // the linter reports the overlap.
  const operatorByOrigin = new Map<string, string>()
  for (const [label, origins] of Object.entries(policy.operators ?? {})) {
    for (const origin of origins)
      if (!operatorByOrigin.has(origin)) operatorByOrigin.set(origin, label)
  }

  return {
    policy,
    evaluate(verdict, facts): Decision {
      const operator =
        verdict.signatureAgent === undefined
          ? undefined
          : operatorByOrigin.get(verdict.signatureAgent)

      for (const { rule, routes } of rules) {
        if (
          routes !== undefined &&
          !routes.some((r) => matchesRoute(r, facts.method, facts.path))
        ) {
          continue
        }
        if (rule.when !== undefined && !matchesCondition(rule.when, verdict, operator)) continue
        return decision(rule.action, rule.id, verdict, operator)
      }
      // The implicit default is reported as a named rule, never as a blank.
      return decision(policy.default, 'default', verdict, operator)
    },
  }
}

function decision(
  action: Decision['action'],
  ruleId: string,
  verdict: Verdict,
  operator: string | undefined,
): Decision {
  return operator === undefined
    ? { action, ruleId, verdict }
    : { action, ruleId, verdict, operator }
}

/** Fields are ANDed; values within a field are ORed. */
function matchesCondition(
  condition: Condition,
  verdict: Verdict,
  operator: string | undefined,
): boolean {
  if (condition.status !== undefined && !includes(condition.status, verdict.status)) return false
  if (condition.class !== undefined && !includes(condition.class, verdict.class)) return false
  if (condition.reason !== undefined && !includes(condition.reason, verdict.reason)) return false
  if (condition.operator !== undefined) {
    if (operator === undefined || !includes(condition.operator, operator)) return false
  }
  if (condition.origin !== undefined) {
    if (
      verdict.signatureAgent === undefined ||
      !includes(condition.origin, verdict.signatureAgent)
    ) {
      return false
    }
  }
  return true
}

function includes<T extends string>(expected: T | readonly T[], actual: T): boolean {
  return Array.isArray(expected) ? expected.includes(actual) : expected === actual
}
