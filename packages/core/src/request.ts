import type { NormalizedRequest } from './types.js'

export interface RequestInit {
  readonly method: string
  readonly scheme: 'http' | 'https'
  /** `host[:port]` as the client addressed it. */
  readonly authority: string
  /** Raw, not percent-decoded. A leading `/` is added if missing. */
  readonly path: string
  /** Raw, without the leading `?`. */
  readonly query?: string
  readonly headers?:
    | Readonly<Record<string, string | readonly string[] | undefined>>
    | Iterable<readonly [string, string]>
}

/**
 * Build a {@link NormalizedRequest} from plain data.
 *
 * Adapters that already hold headers as a map use this; adapters over a native
 * request object may implement the interface directly to avoid copying.
 *
 * Repeated fields are joined with `", "` in the order received, per RFC 9421
 * §2.1. Values are otherwise untouched — no re-serialization, no reordering.
 */
export function createRequest(init: RequestInit): NormalizedRequest {
  const headers = new Map<string, string>()
  const add = (name: string, value: string): void => {
    const key = name.toLowerCase()
    const existing = headers.get(key)
    headers.set(key, existing === undefined ? value : `${existing}, ${value}`)
  }

  const source = init.headers
  if (source !== undefined) {
    if (Symbol.iterator in Object(source)) {
      for (const [name, value] of source as Iterable<readonly [string, string]>) add(name, value)
    } else {
      for (const [name, value] of Object.entries(
        source as Readonly<Record<string, string | readonly string[] | undefined>>,
      )) {
        if (value === undefined) continue
        if (Array.isArray(value)) for (const v of value) add(name, v)
        else add(name, value as string)
      }
    }
  }

  const path = init.path.startsWith('/') ? init.path : `/${init.path}`
  return {
    method: init.method,
    scheme: init.scheme,
    authority: init.authority,
    path,
    query: init.query ?? '',
    header: (name) => headers.get(name.toLowerCase()),
  }
}
