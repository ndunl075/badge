/**
 * How an adapter decides what the client actually addressed.
 *
 * This is the single most common cause of a bogus `signature_invalid`. The
 * signer signed the authority it dialled; if a load balancer rewrites `Host`,
 * every signature fails and the failure looks cryptographic rather than
 * operational.
 *
 * - `host` — trust the `Host` header. Correct when Badge is the first hop.
 * - `forwarded` — trust `Forwarded` / `X-Forwarded-Host` from the proxy in
 *   front. **Only safe when something you control strips those headers from
 *   client requests**, since otherwise any caller can claim any authority.
 * - `{ fixed }` — a constant. The safest option when the public name is known.
 */
export type AuthoritySource = 'host' | 'forwarded' | { readonly fixed: string }

export type SchemeSource = 'auto' | 'http' | 'https' | 'forwarded'

export interface HeaderLookup {
  (name: string): string | undefined
}

export function resolveAuthority(
  source: AuthoritySource,
  header: HeaderLookup,
): string | undefined {
  if (typeof source === 'object') return source.fixed
  if (source === 'forwarded') {
    const forwarded = firstForwardedHost(header('forwarded'))
    if (forwarded !== undefined) return forwarded
    const xfh = header('x-forwarded-host')
    if (xfh !== undefined) return first(xfh)
  }
  return header('host')
}

export function resolveScheme(
  source: SchemeSource,
  header: HeaderLookup,
  encrypted: boolean,
): 'http' | 'https' {
  if (source === 'http' || source === 'https') return source
  if (source === 'forwarded') {
    const proto = firstForwardedProto(header('forwarded')) ?? first(header('x-forwarded-proto'))
    if (proto === 'http' || proto === 'https') return proto
  }
  return encrypted ? 'https' : 'http'
}

/** RFC 7239 `Forwarded: for=...;host=example.com;proto=https, for=...`. */
function firstForwardedHost(value: string | undefined): string | undefined {
  return forwardedParam(value, 'host')
}

function firstForwardedProto(value: string | undefined): string | undefined {
  return forwardedParam(value, 'proto')?.toLowerCase()
}

function forwardedParam(value: string | undefined, name: string): string | undefined {
  if (value === undefined) return undefined
  // Only the first element matters: it is the hop closest to the client.
  const element = value.split(',')[0] as string
  for (const pair of element.split(';')) {
    const eq = pair.indexOf('=')
    if (eq === -1) continue
    if (pair.slice(0, eq).trim().toLowerCase() !== name) continue
    const raw = pair.slice(eq + 1).trim()
    return raw.startsWith('"') && raw.endsWith('"') && raw.length >= 2 ? raw.slice(1, -1) : raw
  }
  return undefined
}

function first(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  const head = value.split(',')[0]?.trim()
  return head === '' ? undefined : head
}
