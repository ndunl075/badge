/**
 * A profile pins one revision of the Web Bot Auth drafts.
 *
 * The drafts are individual Internet-Drafts, not working-group adopted, and
 * they move — the directory draft has already been renamed once. Encoding their
 * rules as data, in one place, means a new revision is a new profile rather
 * than a scattering of edits through the verifier. Every verdict records which
 * profile judged it, so a log line from six months ago still says which rules
 * applied.
 */
export interface Profile {
  /** Stable identifier recorded in every verdict, e.g. `wba-2026-03`. */
  readonly id: string
  /** Human-readable note on which drafts this profile tracks. */
  readonly tracks: string
  /** The `tag` parameter value that marks a signature as Web Bot Auth. */
  readonly tag: string
  /** Path the key directory is served from, appended to the signature agent origin. */
  readonly directoryPath: string
  /** Media type the directory is expected to carry. */
  readonly directoryMediaType: string
  /** Permitted `alg` parameter values. */
  readonly algorithms: readonly string[]
  /** Components every signature must cover. */
  readonly requiredComponents: readonly string[]
  /** Components that must be covered whenever the request carries that header. */
  readonly requiredComponentsWhenPresent: readonly string[]
  /** Whether `Signature-Agent` is required for key discovery. */
  readonly requireSignatureAgent: boolean
  readonly requireKeyid: boolean
  readonly requireCreated: boolean
  /** A signature with no `expires` is a permanent bearer token. */
  readonly requireExpires: boolean
  /** Ceiling on `expires - created`. The architecture draft RECOMMENDs no more than 24 hours. */
  readonly maxWindowSec: number
}

/**
 * Tracks the drafts as of March 2026.
 *
 * `alg` is a String rather than a Token in the Web Bot Auth examples, and the
 * minimum covered set is `@authority` plus `signature-agent` when present.
 */
export const WBA_2026_03: Profile = {
  id: 'wba-2026-03',
  tracks:
    'draft-meunier-web-bot-auth-architecture-05, ' +
    'draft-meunier-webbotauth-httpsig-protocol-02, ' +
    'draft-meunier-webbotauth-httpsig-directory-00',
  tag: 'web-bot-auth',
  directoryPath: '/.well-known/http-message-signatures-directory',
  directoryMediaType: 'application/http-message-signatures-directory+json',
  algorithms: ['ed25519'],
  requiredComponents: ['@authority'],
  requiredComponentsWhenPresent: ['signature-agent'],
  requireSignatureAgent: true,
  requireKeyid: true,
  requireCreated: true,
  requireExpires: true,
  maxWindowSec: 86_400,
}

/** The profile used when a caller does not choose one. */
export const DEFAULT_PROFILE = WBA_2026_03

export const PROFILES: ReadonlyMap<string, Profile> = new Map([[WBA_2026_03.id, WBA_2026_03]])

export function getProfile(id: string): Profile | undefined {
  return PROFILES.get(id)
}
