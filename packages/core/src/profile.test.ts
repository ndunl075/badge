import { describe, expect, it } from 'vitest'
import { DEFAULT_PROFILE, PROFILES, WBA_2026_03, getProfile } from './profile.js'

describe('profiles', () => {
  it('pins the Web Bot Auth wire details', () => {
    expect(WBA_2026_03.tag).toBe('web-bot-auth')
    expect(WBA_2026_03.directoryPath).toBe('/.well-known/http-message-signatures-directory')
    expect(WBA_2026_03.directoryMediaType).toBe(
      'application/http-message-signatures-directory+json',
    )
    expect(WBA_2026_03.algorithms).toEqual(['ed25519'])
  })

  it('requires the minimum covered component set', () => {
    expect(WBA_2026_03.requiredComponents).toContain('@authority')
    expect(WBA_2026_03.requiredComponentsWhenPresent).toContain('signature-agent')
  })

  it('caps the validity window at the 24 hours the draft recommends', () => {
    expect(WBA_2026_03.maxWindowSec).toBe(86_400)
  })

  it('is resolvable by id, and every registered profile matches its own key', () => {
    expect(getProfile('wba-2026-03')).toBe(WBA_2026_03)
    expect(getProfile('nope')).toBeUndefined()
    for (const [id, profile] of PROFILES) expect(profile.id).toBe(id)
  })

  it('defaults to a registered profile', () => {
    expect(PROFILES.get(DEFAULT_PROFILE.id)).toBe(DEFAULT_PROFILE)
  })
})
