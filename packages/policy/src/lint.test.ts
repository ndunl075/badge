import { describe, expect, it } from 'vitest'
import { DEFAULT_POLICY, EXAMPLE_POLICY } from './defaults.js'
import { lintPolicy, reasonsMatching } from './lint.js'
import type { Policy } from './types.js'

const codes = (policy: Policy): string[] => lintPolicy(policy).map((d) => d.code)

const base: Policy = { version: 1, default: 'log-only' }

describe('lintPolicy', () => {
  it('reports nothing alarming about the shipped example', () => {
    expect(lintPolicy(EXAMPLE_POLICY).filter((d) => d.severity === 'warning')).toEqual([])
  })

  it('notes that the default policy enforces nothing', () => {
    expect(codes(DEFAULT_POLICY)).toContain('policy-is-observe-only')
  })

  // The most dangerous single setting in the file.
  it('warns that a deny default blocks every browser', () => {
    expect(codes({ ...base, default: 'deny' })).toContain('default-denies-everything')
  })

  // The footgun the whole class axis exists to prevent.
  it('warns when a deny rule would also catch our own failures', () => {
    const policy: Policy = {
      ...base,
      rules: [{ id: 'strict', action: 'deny', when: { status: 'claimed' } }],
    }
    const diagnostic = lintPolicy(policy).find((d) => d.code === 'deny-on-unverifiable')
    expect(diagnostic).toBeDefined()
    expect(diagnostic?.message).toContain('directory_')
    expect(diagnostic?.ruleId).toBe('strict')
  })

  it('stays quiet when the deny rule is narrowed to untrusted', () => {
    const policy: Policy = {
      ...base,
      rules: [{ id: 'narrow', action: 'deny', when: { class: 'untrusted' } }],
    }
    expect(codes(policy)).not.toContain('deny-on-unverifiable')
  })

  it('does not warn about log-only rules that match unverifiable', () => {
    const policy: Policy = {
      ...base,
      rules: [{ id: 'watch', action: 'log-only', when: { status: 'claimed' } }],
    }
    expect(codes(policy)).not.toContain('deny-on-unverifiable')
  })

  it('reports a condition no verdict can satisfy', () => {
    const policy: Policy = {
      ...base,
      rules: [{ id: 'never', action: 'deny', when: { status: 'verified', class: 'untrusted' } }],
    }
    expect(codes(policy)).toContain('impossible-condition')
  })

  it('reports rules shadowed by an earlier catch-all', () => {
    const policy: Policy = {
      ...base,
      rules: [
        { id: 'everything', action: 'log-only' },
        { id: 'shadowed', action: 'deny', when: { class: 'untrusted' } },
      ],
    }
    const diagnostic = lintPolicy(policy).find((d) => d.code === 'unreachable-rule')
    expect(diagnostic?.ruleId).toBe('shadowed')
  })

  it('does not call a catch-all in last position unreachable', () => {
    const policy: Policy = {
      ...base,
      rules: [
        { id: 'specific', action: 'deny', when: { class: 'untrusted' } },
        { id: 'everything', action: 'log-only' },
      ],
    }
    expect(codes(policy)).not.toContain('unreachable-rule')
  })

  it('reports a duplicated condition and route set', () => {
    const policy: Policy = {
      ...base,
      rules: [
        { id: 'a', action: 'deny', when: { class: 'untrusted' }, routes: ['GET /x', 'GET /y'] },
        { id: 'b', action: 'allow', when: { class: 'untrusted' }, routes: ['GET /y', 'GET /x'] },
      ],
    }
    const diagnostic = lintPolicy(policy).find((d) => d.code === 'duplicate-rule')
    expect(diagnostic?.ruleId).toBe('b')
  })

  it('reports an unparseable route', () => {
    const policy: Policy = {
      ...base,
      rules: [{ id: 'bad', action: 'deny', when: { class: 'untrusted' }, routes: ['docs'] }],
    }
    expect(codes(policy)).toContain('invalid-route')
  })

  it('reports operators nothing refers to', () => {
    const policy: Policy = { ...base, operators: { ghost: ['https://ghost.example'] } }
    expect(codes(policy)).toContain('unused-operator')
  })

  it('reports an origin claimed by two operators', () => {
    const policy: Policy = {
      ...base,
      operators: { a: ['https://shared.example'], b: ['https://shared.example'] },
      rules: [
        { id: 'r1', action: 'allow', when: { operator: 'a' } },
        { id: 'r2', action: 'allow', when: { operator: 'b' } },
      ],
    }
    const diagnostic = lintPolicy(policy).find((d) => d.code === 'ambiguous-origin')
    expect(diagnostic?.message).toContain('shared.example')
  })
})

describe('reasonsMatching', () => {
  it('narrows to exactly the reasons a class admits', () => {
    expect(reasonsMatching({ class: 'ok' })).toEqual(['ok'])
  })

  it('finds no reason for a contradiction', () => {
    expect(reasonsMatching({ status: 'unknown', class: 'untrusted' })).toEqual([])
  })

  it('shows that status "claimed" sweeps in our own failures', () => {
    expect(reasonsMatching({ status: 'claimed' })).toContain('directory_timeout')
  })
})
