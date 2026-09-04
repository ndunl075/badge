import { describe, expect, it } from 'vitest'
import { REASON_CODES, reasonInfo } from './reasons.js'
import { verdictFor } from './verdict.js'

const profile = 'test-profile'

describe('verdictFor', () => {
  it('derives status and class from the reason for every code', () => {
    for (const code of REASON_CODES) {
      const verdict = verdictFor(code, { profile })
      expect(verdict.reason).toBe(code)
      expect(verdict.status).toBe(reasonInfo(code).status)
      expect(verdict.class).toBe(reasonInfo(code).class)
    }
  })

  it('always records the profile that judged the request', () => {
    expect(verdictFor('ok', { profile }).profile).toBe(profile)
  })

  it('omits absent optionals rather than setting them undefined', () => {
    const verdict = verdictFor('no_signature_fields', { profile })
    expect('signatureAgent' in verdict).toBe(false)
    expect('keyid' in verdict).toBe(false)
    expect('covered' in verdict).toBe(false)
  })

  it('carries the details it was given', () => {
    const verdict = verdictFor('signature_invalid', {
      profile,
      signatureAgent: 'https://agent.example',
      keyid: 'thumbprint',
      label: 'sig1',
      created: 100,
      expires: 160,
      covered: ['@authority', 'signature-agent'],
      timing: { totalUs: 42, directoryUs: 30, cache: 'hit' },
    })
    expect(verdict).toMatchObject({
      signatureAgent: 'https://agent.example',
      keyid: 'thumbprint',
      label: 'sig1',
      created: 100,
      expires: 160,
      covered: ['@authority', 'signature-agent'],
      timing: { totalUs: 42, directoryUs: 30, cache: 'hit' },
    })
  })

  it('defaults timing so the field is never missing', () => {
    expect(verdictFor('ok', { profile }).timing).toEqual({ totalUs: 0 })
  })
})
