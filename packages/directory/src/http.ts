import { lookup as dnsLookup } from 'node:dns'
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { isIP, type LookupFunction } from 'node:net'
import { isPublicAddress } from './address.js'

export type HttpFailureKind = 'timeout' | 'too-large' | 'blocked' | 'network'

export class HttpClientError extends Error {
  override readonly name = 'HttpClientError'
  constructor(
    message: string,
    readonly kind: HttpFailureKind,
  ) {
    super(message)
  }
}

export interface HttpResponse {
  readonly status: number
  /** Lowercased field names. Repeated fields are comma-joined. */
  readonly headers: ReadonlyMap<string, string>
  readonly body: Uint8Array
}

export interface HttpRequestOptions {
  /** Total budget for connect plus read. */
  readonly timeoutMs: number
  /** Hard cap on the response body. Exceeding it aborts the transfer. */
  readonly maxBytes: number
  readonly accept?: string
}

export interface HttpClient {
  get(url: string, options: HttpRequestOptions): Promise<HttpResponse>
}

export interface NodeHttpClientOptions {
  /**
   * Permit connections to loopback, private, and link-local addresses.
   *
   * Off by default and it should stay off. Turn it on only for a directory you
   * host yourself inside a trusted network — it removes the guard that stops an
   * attacker-supplied `Signature-Agent` from pointing Badge at a cloud metadata
   * endpoint or an internal admin panel.
   */
  readonly allowPrivateAddresses?: boolean
  /** Additional trusted CA certificates, for an internal directory behind a private CA. */
  readonly ca?: string | readonly string[]
}

/**
 * A DNS lookup that refuses to resolve to an address we will not connect to.
 *
 * Passing this to `request()` is what makes the guard airtight: Node connects
 * to exactly the address this returns, so there is no window between the check
 * and the connection for DNS to be rebound to something else.
 */
export function guardedLookup(allowPrivateAddresses = false): LookupFunction {
  return ((hostname, options, callback) => {
    dnsLookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
      if (err !== null) {
        callback(err, '', 0)
        return
      }
      const safe = addresses.filter((a) => allowPrivateAddresses || isPublicAddress(a.address))
      if (safe.length === 0) {
        const blocked = addresses.map((a) => a.address).join(', ')
        callback(
          new HttpClientError(
            `refusing to connect to a non-public address for ${hostname}: ${blocked || 'no addresses'}`,
            'blocked',
          ),
          '',
          0,
        )
        return
      }
      if (typeof options === 'object' && options.all === true) {
        ;(callback as unknown as (e: null, a: typeof safe) => void)(null, safe)
        return
      }
      const first = safe[0] as { address: string; family: number }
      callback(null, first.address, first.family)
    })
  }) as LookupFunction
}

/**
 * Reject a URL whose host is a non-public IP literal.
 *
 * The pinned lookup alone is not enough: when the host is already an IP
 * literal, the socket layer connects directly and never calls `lookup`, so
 * `https://169.254.169.254/` would sail straight past it. This closes that
 * path. Hostnames still go through {@link guardedLookup}.
 */
export function assertHostAllowed(hostname: string, allowPrivateAddresses = false): void {
  if (allowPrivateAddresses) return
  // URL.hostname keeps the brackets on an IPv6 literal.
  const host = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname
  if (isIP(host) === 0) return
  if (!isPublicAddress(host)) {
    throw new HttpClientError(`refusing to connect to a non-public address: ${host}`, 'blocked')
  }
}

/**
 * Perform a GET with hard limits, following no redirects.
 *
 * Redirects are not followed on purpose. A redirect is the obvious way around
 * an origin check: fetch `https://attacker.example/...`, get a 302 to
 * `http://169.254.169.254/`, and a client that follows it has just done the
 * attacker's request for them. The key directory lives at a fixed path on the
 * origin the caller named; there is nowhere legitimate to redirect to.
 *
 * Exported for tests, which exercise the limits over plain HTTP. Callers should
 * use {@link nodeHttpClient}, which additionally enforces https.
 */
export async function requestWithLimits(
  url: string,
  options: HttpRequestOptions,
  clientOptions: NodeHttpClientOptions = {},
): Promise<HttpResponse> {
  const target = new URL(url)
  assertHostAllowed(target.hostname, clientOptions.allowPrivateAddresses)
  const send = target.protocol === 'https:' ? httpsRequest : httpRequest

  return await new Promise<HttpResponse>((resolve, reject) => {
    let settled = false
    const finish = (fn: () => void): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      fn()
    }

    const req = send(
      target,
      {
        method: 'GET',
        lookup: guardedLookup(clientOptions.allowPrivateAddresses),
        headers: {
          accept: options.accept ?? '*/*',
          'accept-encoding': 'identity',
        },
        ...(clientOptions.ca === undefined ? {} : { ca: clientOptions.ca as string | string[] }),
      },
      (res) => {
        const chunks: Buffer[] = []
        let received = 0

        // A Content-Length that already exceeds the cap is refused before a
        // single byte of body is read.
        const declared = Number(res.headers['content-length'])
        if (Number.isFinite(declared) && declared > options.maxBytes) {
          res.destroy()
          finish(() => {
            reject(new HttpClientError('directory declares a body over the size cap', 'too-large'))
          })
          return
        }

        res.on('data', (chunk: Buffer) => {
          received += chunk.length
          if (received > options.maxBytes) {
            res.destroy()
            req.destroy()
            finish(() => {
              reject(new HttpClientError('directory body exceeded the size cap', 'too-large'))
            })
            return
          }
          chunks.push(chunk)
        })
        res.on('end', () => {
          const headers = new Map<string, string>()
          for (const [name, value] of Object.entries(res.headers)) {
            if (value === undefined) continue
            headers.set(name.toLowerCase(), Array.isArray(value) ? value.join(', ') : value)
          }
          finish(() => {
            resolve({
              status: res.statusCode ?? 0,
              headers,
              body: new Uint8Array(Buffer.concat(chunks)),
            })
          })
        })
        res.on('error', (err) => {
          finish(() => {
            reject(toClientError(err))
          })
        })
      },
    )

    const timer = setTimeout(() => {
      req.destroy()
      finish(() => {
        reject(new HttpClientError(`directory fetch exceeded ${options.timeoutMs}ms`, 'timeout'))
      })
    }, options.timeoutMs)
    timer.unref?.()

    req.on('error', (err) => {
      finish(() => {
        reject(toClientError(err))
      })
    })
    req.end()
  })
}

function toClientError(err: unknown): HttpClientError {
  if (err instanceof HttpClientError) return err
  const message = err instanceof Error ? err.message : String(err)
  return new HttpClientError(message, 'network')
}

/**
 * The default transport: https only, no redirects, a pinned public-address
 * lookup, a hard timeout, and a body cap.
 */
export function nodeHttpClient(clientOptions: NodeHttpClientOptions = {}): HttpClient {
  return {
    async get(url, options) {
      let target: URL
      try {
        target = new URL(url)
      } catch {
        throw new HttpClientError(`not a valid URL: ${url}`, 'blocked')
      }
      if (target.protocol !== 'https:') {
        throw new HttpClientError(`refusing to fetch a non-https directory: ${url}`, 'blocked')
      }
      return await requestWithLimits(url, options, clientOptions)
    },
  }
}
