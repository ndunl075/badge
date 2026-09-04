import type { Policy } from './types.js'

/**
 * The policy Badge applies when an operator has not written one, and the
 * starting point `badge policy init` emits.
 *
 * It observes and reports; it denies nothing. An operator earns the confidence
 * to enforce by reading their own decision log first, not by trusting a default
 * someone else chose for their traffic.
 */
export const DEFAULT_POLICY: Policy = {
  version: 1,
  default: 'log-only',
  operators: {},
  rules: [],
}

/**
 * A worked example, used in the docs and the CLI's `--example` output.
 *
 * The first two rules are the ones that matter and the ones people get wrong:
 * a forged signature is hostile, and our own inability to check is not.
 */
export const EXAMPLE_POLICY: Policy = {
  version: 1,
  default: 'log-only',
  operators: {
    example: ['https://agent.example'],
  },
  rules: [
    { id: 'forgeries-are-hostile', action: 'deny', when: { class: 'untrusted' } },
    { id: 'our-outage-is-not-their-fault', action: 'log-only', when: { class: 'unverifiable' } },
    {
      id: 'docs-open-to-known-agents',
      action: 'allow',
      when: { status: 'verified', operator: 'example' },
      routes: ['GET /docs/**', 'GET /blog/**'],
    },
    {
      // Denies any request carrying a Web Bot Auth claim Badge could actually
      // evaluate. `unverifiable` is deliberately absent: a directory timeout is
      // Badge's failure, not the caller's, and denying on it would take
      // checkout down whenever egress hiccups. An operator who wants the
      // stricter reading adds `unverifiable` here and accepts the lint warning.
      id: 'no-agents-at-checkout',
      action: 'deny',
      when: { class: ['ok', 'untrusted', 'malformed', 'expired'] },
      routes: ['POST /checkout/**'],
    },
  ],
}
