import { verdictFor, type RequestFacts, type Verdict } from '@badge/core'
import { describe, expect, it } from 'vitest'
import { DEFAULT_POLICY, EXAMPLE_POLICY } from './defaults.js'
import { compilePolicy } from './evaluate.js'
import { parsePolicy } from './parse.js'
import type { Policy } from './types.js'

const facts = (method = 'GET', path = '/docs/intro'): RequestFacts => ({
  method,
  path,
  authority: 'example.com',
})

const verdict = (reason: Parameters<typeof verdictFor>[0], signatureAgent?: string): Verdict =>
  verdictFor(reason, {
    profile: 'test',
    ...(signatureAgent === undefined ? {} : { signatureAgent }),
  })

const evaluate = (policy: Policy, v: Verdict, f: RequestFacts = facts()) =>
  compilePolicy(parsePolicy(policy)).evaluate(v, f)

describe('policy evaluation', () => {
  it('falls back to the default and names it', () => {
    const decision = evaluate(DEFAULT_POLICY, verdict('ok'))
    expect(decision).toMatchObject({ action: 'log-only', ruleId: 'default' })
  })

  // Installing Badge cannot break a live site.
  it('denies nothing under the shipped default policy', () => {
    for (const reason of [
      'ok',
      'signature_invalid',
      'directory_timeout',
      'no_signature_fields',
    ] as const) {
      expect(evaluate(DEFAULT_POLICY, verdict(reason)).action).toBe('log-only')
    }
  })

  it('takes the first matching rule', () => {
    const policy: Policy = {
      version: 1,
      default: 'log-only',
      rules: [
        { id: 'first', action: 'allow', when: { class: 'untrusted' } },
        { id: 'second', action: 'deny', when: { class: 'untrusted' } },
      ],
    }
    expect(evaluate(policy, verdict('signature_invalid')).ruleId).toBe('first')
  })

  it('ANDs fields within a condition', () => {
    const policy: Policy = {
      version: 1,
      default: 'log-only',
      operators: { example: ['https://agent.example'] },
      rules: [
        {
          id: 'both',
          action: 'allow',
          when: { status: 'verified', operator: 'example' },
        },
      ],
    }
    expect(evaluate(policy, verdict('ok', 'https://agent.example')).ruleId).toBe('both')
    expect(evaluate(policy, verdict('ok', 'https://other.example')).ruleId).toBe('default')
    expect(evaluate(policy, verdict('signature_invalid', 'https://agent.example')).ruleId).toBe(
      'default',
    )
  })

  it('ORs values within a field', () => {
    const policy: Policy = {
      version: 1,
      default: 'log-only',
      rules: [{ id: 'either', action: 'deny', when: { status: ['verified', 'claimed'] } }],
    }
    expect(evaluate(policy, verdict('ok')).ruleId).toBe('either')
    expect(evaluate(policy, verdict('signature_invalid')).ruleId).toBe('either')
    expect(evaluate(policy, verdict('no_signature_fields')).ruleId).toBe('default')
  })

  it('resolves the operator label and reports it on the decision', () => {
    const decision = evaluate(EXAMPLE_POLICY, verdict('ok', 'https://agent.example'))
    expect(decision.operator).toBe('example')
  })

  it('omits the operator when the origin is unknown', () => {
    const decision = evaluate(EXAMPLE_POLICY, verdict('ok', 'https://stranger.example'))
    expect('operator' in decision).toBe(false)
  })

  it('scopes a rule to its routes', () => {
    const decision = (method: string, path: string) =>
      evaluate(EXAMPLE_POLICY, verdict('ok', 'https://agent.example'), facts(method, path))
    expect(decision('GET', '/docs/intro').action).toBe('allow')
    expect(decision('GET', '/admin').action).toBe('log-only')
    expect(decision('POST', '/checkout/pay').action).toBe('deny')
  })

  it('applies a rule with no routes everywhere', () => {
    const policy: Policy = {
      version: 1,
      default: 'log-only',
      rules: [{ id: 'everywhere', action: 'deny', when: { class: 'untrusted' } }],
    }
    expect(evaluate(policy, verdict('signature_invalid'), facts('POST', '/x')).ruleId).toBe(
      'everywhere',
    )
  })

  // The two rules the architecture argues hardest for.
  it('separates a forgery from our own outage', () => {
    const forged = evaluate(EXAMPLE_POLICY, verdict('signature_invalid', 'https://agent.example'))
    const outage = evaluate(EXAMPLE_POLICY, verdict('directory_timeout', 'https://agent.example'))
    expect(forged.action).toBe('deny')
    expect(outage.action).toBe('log-only')
  })

  it('carries the verdict through to the decision', () => {
    const v = verdict('ok', 'https://agent.example')
    expect(evaluate(EXAMPLE_POLICY, v).verdict).toBe(v)
  })

  it('matches on a raw origin without an operator label', () => {
    const policy: Policy = {
      version: 1,
      default: 'log-only',
      rules: [{ id: 'raw', action: 'allow', when: { origin: 'https://agent.example' } }],
    }
    expect(evaluate(policy, verdict('ok', 'https://agent.example')).ruleId).toBe('raw')
    expect(evaluate(policy, verdict('ok')).ruleId).toBe('default')
  })

  it('never matches an operator or origin condition when nothing was claimed', () => {
    const policy: Policy = {
      version: 1,
      default: 'log-only',
      operators: { example: ['https://agent.example'] },
      rules: [{ id: 'op', action: 'allow', when: { operator: 'example' } }],
    }
    expect(evaluate(policy, verdict('no_signature_fields')).ruleId).toBe('default')
  })
})
