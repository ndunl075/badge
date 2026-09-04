import { describe, expect, it } from 'vitest'
import { EXAMPLE_POLICY } from './defaults.js'
import { parsePolicy } from './parse.js'
import { PolicyError } from './types.js'

const minimal = { version: 1, default: 'log-only' }

describe('parsePolicy', () => {
  it('accepts a minimal policy', () => {
    expect(parsePolicy(minimal)).toMatchObject({ version: 1, default: 'log-only' })
  })

  it('round trips the shipped example', () => {
    expect(parsePolicy(JSON.parse(JSON.stringify(EXAMPLE_POLICY)))).toEqual(
      parsePolicy(EXAMPLE_POLICY),
    )
  })

  it('normalizes a single condition value into a list', () => {
    const policy = parsePolicy({
      ...minimal,
      rules: [{ id: 'r', action: 'deny', when: { class: 'untrusted' } }],
    })
    expect(policy.rules?.[0]?.when?.class).toEqual(['untrusted'])
  })

  // A typo that silently falls through to the default is the worst possible
  // failure: the policy looks like it is enforcing and is not.
  it.each([
    ['a missing version', { default: 'log-only' }, 'version'],
    ['a wrong version', { version: 2, default: 'log-only' }, 'version'],
    ['a missing default', { version: 1 }, 'default'],
    ['a misspelled action', { version: 1, default: 'log_only' }, 'default'],
    [
      'an unknown rule key',
      { ...minimal, rules: [{ id: 'r', action: 'deny', unless: {} }] },
      'rules[0]',
    ],
    [
      'an unknown condition key',
      { ...minimal, rules: [{ id: 'r', action: 'deny', when: { klass: 'untrusted' } }] },
      'rules[0].when',
    ],
    [
      'an unknown status value',
      { ...minimal, rules: [{ id: 'r', action: 'deny', when: { status: 'sketchy' } }] },
      'rules[0].when.status',
    ],
    [
      'an unknown reason code',
      { ...minimal, rules: [{ id: 'r', action: 'deny', when: { reason: 'nope' } }] },
      'rules[0].when.reason',
    ],
    [
      'an empty condition',
      { ...minimal, rules: [{ id: 'r', action: 'deny', when: {} }] },
      'rules[0].when',
    ],
    ['a rule with no id', { ...minimal, rules: [{ action: 'deny' }] }, 'rules[0].id'],
    [
      'duplicate rule ids',
      {
        ...minimal,
        rules: [
          { id: 'r', action: 'deny' },
          { id: 'r', action: 'allow' },
        ],
      },
      'rules[1].id',
    ],
    [
      'an operator reference that does not exist',
      { ...minimal, rules: [{ id: 'r', action: 'allow', when: { operator: 'ghost' } }] },
      'rules[0].when.operator',
    ],
  ])('rejects %s', (_label, input, path) => {
    try {
      parsePolicy(input)
      expect.unreachable('should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(PolicyError)
      expect((err as PolicyError).path).toBe(path)
    }
  })

  // An origin with a trailing slash silently fails to match a normalized
  // origin, producing a policy that looks right and does nothing.
  it.each([
    'https://agent.example/',
    'https://agent.example/path',
    'http://agent.example',
    'agent.example',
  ])('rejects the unmatchable origin %s', (origin) => {
    expect(() => parsePolicy({ ...minimal, operators: { a: [origin] } })).toThrow(PolicyError)
  })

  it('accepts an origin with an explicit port', () => {
    const policy = parsePolicy({ ...minimal, operators: { a: ['https://agent.example:8443'] } })
    expect(policy.operators?.['a']).toEqual(['https://agent.example:8443'])
  })

  it.each([null, 42, 'nope', []])('rejects a non-object document: %s', (input) => {
    expect(() => parsePolicy(input)).toThrow(PolicyError)
  })
})
