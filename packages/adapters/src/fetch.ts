import { createRequest, type Decision, type NormalizedRequest } from '@badge/core'
import type { Badge } from '@badge/middleware'
import {
  resolveAuthority,
  resolveScheme,
  type AuthoritySource,
  type SchemeSource,
} from './authority.js'

export interface FetchAdapterOptions {
  /**
   * Defaults to `url`, taking the authority from the request URL.
   *
   * On Workers, Deno and Bun the URL is the one the client addressed, which is
   * what the signer signed. Behind a proxy that rewrites it, switch to
   * `forwarded` or a fixed value.
   */
  readonly authority?: 'url' | AuthoritySource
  readonly scheme?: 'url' | SchemeSource
  readonly denyStatus?: number
  readonly denyBody?: string
  /** Off by default: in production these are a policy oracle. */
  readonly debugHeaders?: boolean
  readonly onDecision?: (decision: Decision, request: Request) => void
}

export function fromFetchRequest(
  request: Request,
  options: FetchAdapterOptions = {},
): NormalizedRequest {
  const url = new URL(request.url)
  const lookup = (name: string): string | undefined => request.headers.get(name) ?? undefined

  const authoritySource = options.authority ?? 'url'
  const schemeSource = options.scheme ?? 'url'

  const authority =
    authoritySource === 'url' ? url.host : (resolveAuthority(authoritySource, lookup) ?? url.host)
  const scheme =
    schemeSource === 'url'
      ? url.protocol === 'https:'
        ? 'https'
        : 'http'
      : resolveScheme(schemeSource, lookup, url.protocol === 'https:')

  return createRequest({
    method: request.method,
    scheme,
    authority,
    path: url.pathname,
    query: url.search.startsWith('?') ? url.search.slice(1) : url.search,
    headers: [...request.headers.entries()] as [string, string][],
  })
}

/**
 * Middleware for any fetch-style runtime: Workers, Deno, Bun, Hono.
 *
 * `next` produces the response the application would have returned; Badge only
 * decides whether to call it.
 */
export function badgeFetchMiddleware(
  badge: Badge,
  options: FetchAdapterOptions = {},
): (request: Request, next: () => Promise<Response>) => Promise<Response> {
  return async (request, next) => {
    const decision = await badge.inspect(fromFetchRequest(request, options))
    options.onDecision?.(decision, request)

    const debug: Record<string, string> =
      options.debugHeaders === true
        ? {
            'x-badge-status': decision.verdict.status,
            'x-badge-reason': decision.verdict.reason,
            'x-badge-rule': decision.ruleId,
          }
        : {}

    if (decision.action === 'deny') {
      return new Response(options.denyBody ?? 'Forbidden', {
        status: options.denyStatus ?? 403,
        headers: {
          // Specific to this caller's credentials; never store it in a shared cache.
          'cache-control': 'no-store',
          'content-type': 'text/plain; charset=utf-8',
          ...debug,
        },
      })
    }

    const response = await next()
    for (const [name, value] of Object.entries(debug)) response.headers.set(name, value)
    return response
  }
}

/** The shape of a Hono context that this adapter needs, structurally typed to avoid the dependency. */
export interface HonoLikeContext {
  readonly req: { readonly raw: Request }
}

/**
 * Hono middleware. Returning a Response short-circuits the chain; returning
 * nothing lets the handler run.
 */
export function badgeHono(
  badge: Badge,
  options: FetchAdapterOptions = {},
): (c: HonoLikeContext, next: () => Promise<void>) => Promise<Response | undefined> {
  return async (c, next) => {
    const decision = await badge.inspect(fromFetchRequest(c.req.raw, options))
    options.onDecision?.(decision, c.req.raw)
    if (decision.action === 'deny') {
      return new Response(options.denyBody ?? 'Forbidden', {
        status: options.denyStatus ?? 403,
        headers: { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' },
      })
    }
    await next()
    return undefined
  }
}
