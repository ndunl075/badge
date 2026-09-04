import type { IncomingMessage, ServerResponse } from 'node:http'
import { createRequest, type Decision, type NormalizedRequest } from '@badge/core'
import type { Badge } from '@badge/middleware'
import {
  resolveAuthority,
  resolveScheme,
  type AuthoritySource,
  type SchemeSource,
} from './authority.js'

/** How to turn a Node request into a {@link NormalizedRequest}. */
export interface NodeRequestOptions {
  /** See {@link AuthoritySource}. Defaults to `host`. */
  readonly authority?: AuthoritySource
  readonly scheme?: SchemeSource
}

export interface NodeAdapterOptions extends NodeRequestOptions {
  /** Status returned when the policy denies. */
  readonly denyStatus?: number
  readonly denyBody?: string
  /**
   * Add `X-Badge-*` headers describing the decision.
   *
   * Off by default. In production these hand an attacker a policy oracle: they
   * can probe until they learn exactly which rule fires and why.
   */
  readonly debugHeaders?: boolean
  /** Called for every decision, before the response is touched. */
  readonly onDecision?: (decision: Decision, req: IncomingMessage) => void
}

/**
 * Build a {@link NormalizedRequest} from a Node request.
 *
 * Headers come from `rawHeaders` rather than `headers`: Node discards
 * duplicates of some field names when building the parsed object, and a covered
 * field that was sent twice must reach the signature base exactly as it
 * arrived.
 */
export function fromNodeRequest(
  req: IncomingMessage,
  options: NodeRequestOptions = {},
): NormalizedRequest {
  const raw = req.rawHeaders
  const pairs: [string, string][] = []
  for (let i = 0; i + 1 < raw.length; i += 2) {
    pairs.push([raw[i] as string, raw[i + 1] as string])
  }
  const lookup = (name: string): string | undefined => {
    const wanted = name.toLowerCase()
    const values = pairs.filter(([n]) => n.toLowerCase() === wanted).map(([, v]) => v)
    return values.length === 0 ? undefined : values.join(', ')
  }

  const target = req.url ?? '/'
  const questionMark = target.indexOf('?')
  const encrypted = (req.socket as { encrypted?: boolean }).encrypted === true

  return createRequest({
    method: req.method ?? 'GET',
    scheme: resolveScheme(options.scheme ?? 'auto', lookup, encrypted),
    authority: resolveAuthority(options.authority ?? 'host', lookup) ?? '',
    path: questionMark === -1 ? target : target.slice(0, questionMark),
    query: questionMark === -1 ? '' : target.slice(questionMark + 1),
    headers: pairs,
  })
}

/**
 * Connect-style middleware, which covers raw `node:http` and Express.
 *
 * The whole adapter is: build a request, call `inspect`, apply the result. No
 * verification logic lives here, by design — every framework must reach the
 * same decision for the same request.
 */
export function badgeNodeMiddleware(
  badge: Badge,
  options: NodeAdapterOptions = {},
): (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => void {
  return (req, res, next) => {
    void (async () => {
      let decision: Decision
      try {
        decision = await badge.inspect(fromNodeRequest(req, options))
      } catch (err) {
        // Badge failing must never take the site down with it.
        next(err)
        return
      }

      options.onDecision?.(decision, req)

      if (options.debugHeaders === true) {
        res.setHeader('x-badge-status', decision.verdict.status)
        res.setHeader('x-badge-reason', decision.verdict.reason)
        res.setHeader('x-badge-rule', decision.ruleId)
      }

      if (decision.action !== 'deny') {
        next()
        return
      }

      // A denial is specific to this caller's credentials, so it must never be
      // stored by a shared cache in front of the origin.
      res.statusCode = options.denyStatus ?? 403
      res.setHeader('cache-control', 'no-store')
      res.setHeader('content-type', 'text/plain; charset=utf-8')
      res.end(options.denyBody ?? 'Forbidden')
    })()
  }
}
