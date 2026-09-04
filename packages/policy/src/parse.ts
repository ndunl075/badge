import type { Action, FailureClass, ReasonCode, Status } from '@badge/core'
import { REASON_CODES } from '@badge/core'
import { PolicyError, type Condition, type Policy, type Rule } from './types.js'

const ACTIONS: readonly Action[] = ['allow', 'deny', 'log-only']
const STATUSES: readonly Status[] = ['verified', 'claimed', 'unknown']
const CLASSES: readonly FailureClass[] = [
  'ok',
  'absent',
  'malformed',
  'expired',
  'untrusted',
  'unverifiable',
]

/**
 * Validate an untrusted object into a {@link Policy}.
 *
 * Strict on purpose: an unknown key is an error, not a shrug. A policy with a
 * typo in `action` that silently falls through to the default is the worst
 * possible failure — it looks like it is enforcing and is not.
 */
export function parsePolicy(input: unknown): Policy {
  const doc = requireObject(input, 'policy')

  if (doc['version'] !== 1) {
    throw new PolicyError('version must be 1', 'version')
  }
  const fallback = requireEnum(doc['default'], ACTIONS, 'default')

  const operators: Record<string, readonly string[]> = {}
  const rawOperators = doc['operators']
  if (rawOperators !== undefined) {
    const map = requireObject(rawOperators, 'operators')
    for (const [label, origins] of Object.entries(map)) {
      const path = `operators.${label}`
      if (!Array.isArray(origins)) throw new PolicyError('must be an array of origins', path)
      operators[label] = origins.map((origin, i) => requireOrigin(origin, `${path}[${i}]`))
    }
  }

  const rules: Rule[] = []
  const rawRules = doc['rules']
  if (rawRules !== undefined) {
    if (!Array.isArray(rawRules)) throw new PolicyError('must be an array', 'rules')
    const ids = new Set<string>()
    rawRules.forEach((raw, index) => {
      const rule = parseRule(raw, `rules[${index}]`, operators)
      if (ids.has(rule.id)) {
        throw new PolicyError(`duplicate rule id: ${rule.id}`, `rules[${index}].id`)
      }
      ids.add(rule.id)
      rules.push(rule)
    })
  }

  return { version: 1, default: fallback, operators, rules }
}

const RULE_KEYS = new Set(['id', 'action', 'when', 'routes'])
const CONDITION_KEYS = new Set(['status', 'class', 'reason', 'operator', 'origin'])

function parseRule(
  input: unknown,
  path: string,
  operators: Readonly<Record<string, readonly string[]>>,
): Rule {
  const raw = requireObject(input, path)
  rejectUnknownKeys(raw, RULE_KEYS, path)

  const id = raw['id']
  if (typeof id !== 'string' || id.trim() === '') {
    throw new PolicyError('id must be a non-empty string', `${path}.id`)
  }
  const action = requireEnum(raw['action'], ACTIONS, `${path}.action`)

  const rule: {
    -readonly [K in keyof Rule]: Rule[K]
  } = { id, action }

  const routes = raw['routes']
  if (routes !== undefined) {
    if (!Array.isArray(routes)) throw new PolicyError('routes must be an array', `${path}.routes`)
    rule.routes = routes.map((route, i) => {
      if (typeof route !== 'string') {
        throw new PolicyError('route must be a string', `${path}.routes[${i}]`)
      }
      return route
    })
  }

  const when = raw['when']
  if (when !== undefined) rule.when = parseCondition(when, `${path}.when`, operators)

  return rule
}

function parseCondition(
  input: unknown,
  path: string,
  operators: Readonly<Record<string, readonly string[]>>,
): Condition {
  const raw = requireObject(input, path)
  rejectUnknownKeys(raw, CONDITION_KEYS, path)

  const condition: {
    -readonly [K in keyof Condition]: Condition[K]
  } = {}

  if (raw['status'] !== undefined) {
    condition.status = requireEnumList(raw['status'], STATUSES, `${path}.status`)
  }
  if (raw['class'] !== undefined) {
    condition.class = requireEnumList(raw['class'], CLASSES, `${path}.class`)
  }
  if (raw['reason'] !== undefined) {
    condition.reason = requireEnumList(raw['reason'], REASON_CODES, `${path}.reason`)
  }
  if (raw['operator'] !== undefined) {
    const labels = requireStringList(raw['operator'], `${path}.operator`)
    for (const label of labels) {
      if (!(label in operators)) {
        throw new PolicyError(`unknown operator: ${label}`, `${path}.operator`)
      }
    }
    condition.operator = labels
  }
  if (raw['origin'] !== undefined) {
    const origins = requireStringList(raw['origin'], `${path}.origin`)
    condition.origin = origins.map((origin, i) => requireOrigin(origin, `${path}.origin[${i}]`))
  }

  if (Object.keys(condition).length === 0) {
    throw new PolicyError('condition must constrain something', path)
  }
  return condition
}

function requireObject(input: unknown, path: string): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new PolicyError('must be an object', path)
  }
  return input as Record<string, unknown>
}

function rejectUnknownKeys(
  raw: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  path: string,
): void {
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) throw new PolicyError(`unknown key: ${key}`, path)
  }
}

function requireEnum<T extends string>(input: unknown, values: readonly T[], path: string): T {
  if (typeof input !== 'string' || !(values as readonly string[]).includes(input)) {
    throw new PolicyError(`must be one of ${values.join(', ')}`, path)
  }
  return input as T
}

function requireEnumList<T extends string>(
  input: unknown,
  values: readonly T[],
  path: string,
): T[] {
  return requireStringList(input, path).map((value) => requireEnum(value, values, path))
}

function requireStringList(input: unknown, path: string): string[] {
  const list = Array.isArray(input) ? input : [input]
  return list.map((value) => {
    if (typeof value !== 'string') throw new PolicyError('must be a string', path)
    return value
  })
}

/**
 * Origins are compared literally, so they must be written literally: an https
 * scheme, a host, and nothing else. A trailing slash or a path silently fails
 * to match otherwise, which is a policy that looks right and does nothing.
 */
function requireOrigin(input: unknown, path: string): string {
  if (typeof input !== 'string') throw new PolicyError('origin must be a string', path)
  let url: URL
  try {
    url = new URL(input)
  } catch {
    throw new PolicyError(`origin must be an absolute https URL: ${input}`, path)
  }
  if (url.protocol !== 'https:') {
    throw new PolicyError(`origin must use https: ${input}`, path)
  }
  if (url.origin !== input) {
    throw new PolicyError(`origin must have no path, query or trailing slash: ${input}`, path)
  }
  return url.origin
}

export type { ReasonCode }
