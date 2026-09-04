import { REASON_CODES, reasonInfo, type ReasonCode } from '@badge/core'
import { compileRoute } from './route.js'
import type { Condition, Policy, Rule } from './types.js'

export type Severity = 'warning' | 'info'

export interface Diagnostic {
  readonly code: string
  readonly severity: Severity
  readonly message: string
  /** Where in the document, e.g. `rules[2]`. */
  readonly path: string
  readonly ruleId?: string
}

/**
 * Check a policy for the mistakes that pass validation and then behave badly.
 *
 * Everything here is a warning, never an error: an operator who genuinely wants
 * to deny on `unverifiable` is allowed to, they just have to mean it. The job
 * is to make sure nobody does it by accident.
 */
export function lintPolicy(policy: Policy): Diagnostic[] {
  const diagnostics: Diagnostic[] = []
  const push = (d: Diagnostic): void => {
    diagnostics.push(d)
  }

  // The single most dangerous setting in the file. Ordinary browser traffic is
  // `unknown`, so a deny default blocks every human visitor.
  if (policy.default === 'deny') {
    push({
      code: 'default-denies-everything',
      severity: 'warning',
      path: 'default',
      message:
        'default is "deny", which blocks unsigned traffic — including every ordinary browser. ' +
        'Scope denials to rules unless you mean to run an agents-only site.',
    })
  }

  const rules = policy.rules ?? []
  if (rules.length === 0 && policy.default === 'log-only') {
    push({
      code: 'policy-is-observe-only',
      severity: 'info',
      path: 'rules',
      message: 'No rules and a log-only default: Badge will report decisions but enforce nothing.',
    })
  }

  const usedOperators = new Set<string>()
  const seenShapes = new Map<string, number>()
  let catchAllAt: number | undefined

  rules.forEach((rule, index) => {
    const path = `rules[${index}]`
    for (const label of asList(rule.when?.operator)) usedOperators.add(label)

    if (catchAllAt !== undefined) {
      push({
        code: 'unreachable-rule',
        severity: 'warning',
        path,
        ruleId: rule.id,
        message: `Never evaluated: rules[${catchAllAt}] matches every request.`,
      })
    } else if (isCatchAll(rule)) {
      catchAllAt = index
    }

    const shape = JSON.stringify([rule.when ?? null, [...(rule.routes ?? [])].sort()])
    const firstAt = seenShapes.get(shape)
    if (firstAt === undefined) {
      seenShapes.set(shape, index)
    } else {
      push({
        code: 'duplicate-rule',
        severity: 'warning',
        path,
        ruleId: rule.id,
        message: `Same condition and routes as rules[${firstAt}], so this rule never fires.`,
      })
    }

    if (rule.when !== undefined) {
      const reasons = reasonsMatching(rule.when)
      if (reasons.length === 0) {
        push({
          code: 'impossible-condition',
          severity: 'warning',
          path: `${path}.when`,
          ruleId: rule.id,
          message: 'No verdict can satisfy this condition, so the rule never fires.',
        })
      } else if (rule.action === 'deny') {
        const ourFault = reasons.filter((r) => reasonInfo(r).class === 'unverifiable')
        if (ourFault.length > 0) {
          push({
            code: 'deny-on-unverifiable',
            severity: 'warning',
            path,
            ruleId: rule.id,
            message:
              `Denies on ${ourFault.length} reason(s) that mean Badge could not check, such as ` +
              `${ourFault.slice(0, 3).join(', ')}. This ties the site's availability to the ` +
              "verifier's own uptime. Narrow the condition with class: untrusted if that is not intended.",
          })
        }
      }
    }

    for (const [i, route] of (rule.routes ?? []).entries()) {
      try {
        compileRoute(route, `${path}.routes[${i}]`)
      } catch (err) {
        push({
          code: 'invalid-route',
          severity: 'warning',
          path: `${path}.routes[${i}]`,
          ruleId: rule.id,
          message: err instanceof Error ? err.message : String(err),
        })
      }
    }
  })

  const originOwners = new Map<string, string[]>()
  for (const [label, origins] of Object.entries(policy.operators ?? {})) {
    if (!usedOperators.has(label)) {
      push({
        code: 'unused-operator',
        severity: 'info',
        path: `operators.${label}`,
        message: `Operator "${label}" is defined but no rule refers to it.`,
      })
    }
    for (const origin of origins) {
      originOwners.set(origin, [...(originOwners.get(origin) ?? []), label])
    }
  }
  for (const [origin, labels] of originOwners) {
    if (labels.length > 1) {
      push({
        code: 'ambiguous-origin',
        severity: 'warning',
        path: 'operators',
        message:
          `${origin} is listed under ${labels.join(' and ')}. Only "${labels[0] as string}" ` +
          'will ever be reported.',
      })
    }
  }

  return diagnostics
}

/**
 * Every reason code a condition admits, ignoring operator, origin and routes.
 *
 * Enumerating the closed reason set is what makes `deny-on-unverifiable` exact
 * rather than a guess: a rule saying `status: claimed` catches directory
 * timeouts too, and the operator almost never means that.
 */
export function reasonsMatching(condition: Condition): ReasonCode[] {
  return REASON_CODES.filter((code) => {
    const info = reasonInfo(code)
    if (condition.status !== undefined && !asList(condition.status).includes(info.status)) {
      return false
    }
    if (condition.class !== undefined && !asList(condition.class).includes(info.class)) return false
    if (condition.reason !== undefined && !asList(condition.reason).includes(code)) return false
    return true
  })
}

function isCatchAll(rule: Rule): boolean {
  return rule.when === undefined && (rule.routes === undefined || rule.routes.length === 0)
}

function asList<T extends string>(value: T | readonly T[] | undefined): readonly T[] {
  if (value === undefined) return []
  return Array.isArray(value) ? value : [value as T]
}
