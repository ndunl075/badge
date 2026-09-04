import type { IncomingMessage } from 'node:http'
import type { Decision } from '@badge/core'
import type { Badge } from '@badge/middleware'
import { fromNodeRequest, type NodeAdapterOptions } from './node.js'

/** The parts of a Fastify request and reply this adapter uses, typed structurally. */
export interface FastifyLikeRequest {
  readonly raw: IncomingMessage
}

export interface FastifyLikeReply {
  code(statusCode: number): FastifyLikeReply
  header(name: string, value: string): FastifyLikeReply
  send(payload?: unknown): unknown
}

export interface FastifyAdapterOptions extends Omit<NodeAdapterOptions, 'onDecision'> {
  readonly onDecision?: (decision: Decision, request: FastifyLikeRequest) => void
}

/**
 * An `onRequest` hook.
 *
 * Fastify hooks signal "handled" by sending a reply rather than by not calling
 * `next`, so this returns without touching the reply on allow and log-only.
 */
export function badgeFastify(
  badge: Badge,
  options: FastifyAdapterOptions = {},
): (request: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<void> {
  return async (request, reply) => {
    const decision = await badge.inspect(
      fromNodeRequest(request.raw, {
        ...(options.authority === undefined ? {} : { authority: options.authority }),
        ...(options.scheme === undefined ? {} : { scheme: options.scheme }),
      }),
    )
    options.onDecision?.(decision, request)

    if (options.debugHeaders === true) {
      reply
        .header('x-badge-status', decision.verdict.status)
        .header('x-badge-reason', decision.verdict.reason)
        .header('x-badge-rule', decision.ruleId)
    }
    if (decision.action !== 'deny') return

    reply
      .code(options.denyStatus ?? 403)
      .header('cache-control', 'no-store')
      .header('content-type', 'text/plain; charset=utf-8')
      .send(options.denyBody ?? 'Forbidden')
  }
}
