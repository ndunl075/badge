import { describe, expect, it } from 'vitest'
import { REASONS, REASON_CODES, isOurFault, reasonInfo, type ReasonCode } from './reasons.js'

describe('reason codes', () => {
  it('has at least one code', () => {
    expect(REASON_CODES.length).toBeGreaterThan(0)
  })

  // These three invariants are what let policy match on `class` alone and let
  // operators reason about `status` alone. Breaking any of them silently
  // changes what every deployed policy means.
  it('uses class "ok" for exactly the verified reason', () => {
    for (const code of REASON_CODES) {
      const info = reasonInfo(code)
      expect(info.class === 'ok').toBe(info.status === 'verified')
      expect(info.class === 'ok').toBe(code === 'ok')
    }
  })

  it('treats absent claims as unknown and every other failure as claimed', () => {
    for (const code of REASON_CODES) {
      const info = reasonInfo(code)
      if (info.class === 'absent') expect(info.status).toBe('unknown')
      else if (info.class !== 'ok') expect(info.status).toBe('claimed')
    }
  })

  it('flags exactly the unverifiable codes as our fault', () => {
    for (const code of REASON_CODES) {
      expect(isOurFault(code)).toBe(reasonInfo(code).class === 'unverifiable')
    }
  })

  // A directory that times out or returns garbage must never read as hostile:
  // denying on these wires the site's availability to Badge's own egress.
  it.each([
    'directory_unreachable',
    'directory_timeout',
    'directory_malformed',
    'directory_too_large',
    'nonce_store_unavailable',
    'internal_error',
  ] satisfies ReasonCode[])('classifies %s as unverifiable, not untrusted', (code) => {
    expect(reasonInfo(code).class).toBe('unverifiable')
  })

  // Conversely, a caller-controlled failure must never be excused as ours.
  it.each([
    'signature_invalid',
    'key_not_found',
    'key_expired',
    'key_not_yet_valid',
    'replay_detected',
    'signature_agent_not_allowed',
  ] satisfies ReasonCode[])('classifies %s as untrusted', (code) => {
    expect(reasonInfo(code).class).toBe('untrusted')
  })

  it('exposes every table entry through REASON_CODES', () => {
    expect(new Set(REASON_CODES)).toEqual(new Set(Object.keys(REASONS)))
  })
})
