import type { webcrypto } from 'node:crypto'
import {
  buildSignatureBase,
  createRequest,
  jwkThumbprint,
  sfv,
  type Jwk,
  type NormalizedRequest,
} from '@badge/core'

const { parseItem, serializeInnerList, sf } = sfv

/** An Ed25519 key pair, with the RFC 7638 thumbprint a signer would present as `keyid`. */
export interface SigningKey {
  readonly privateKey: webcrypto.CryptoKey
  /** The public half, as it would appear in a key directory. */
  readonly publicJwk: Jwk
  /** RFC 7638 thumbprint of {@link publicJwk}. */
  readonly keyid: string
}

export async function generateSigningKey(overrides: Partial<Jwk> = {}): Promise<SigningKey> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as webcrypto.CryptoKeyPair
  const exported = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as Jwk
  // Export includes key_ops/ext/alg; keep only what a directory would publish,
  // then let the caller add nbf/exp for rotation tests.
  const publicJwk: Jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: exported.x as string,
    ...overrides,
  }
  return {
    privateKey: pair.privateKey,
    publicJwk,
    keyid: await jwkThumbprint(publicJwk),
  }
}

export interface SignRequestOptions {
  readonly key: SigningKey
  readonly method?: string
  readonly scheme?: 'http' | 'https'
  readonly authority?: string
  readonly path?: string
  readonly query?: string
  readonly headers?: Readonly<Record<string, string>>
  /**
   * Origin published in `Signature-Agent`. Pass `null` to omit the header
   * entirely, which is how you exercise the `signature_agent_missing` path.
   */
  readonly signatureAgent?: string | null
  /** Covered component identifiers, as they would appear in `Signature-Input`. */
  readonly components?: readonly string[]
  readonly created?: number
  readonly expires?: number
  readonly label?: string
  readonly tag?: string | null
  readonly alg?: string | null
  readonly keyid?: string | null
  readonly nonce?: string
  /** Corrupt the signature after signing, to exercise `signature_invalid`. */
  readonly tamperSignature?: boolean
}

export interface SignedRequest {
  readonly request: NormalizedRequest
  readonly headers: Record<string, string>
  /** The exact signature base that was signed — the thing to diff when a test fails. */
  readonly base: string
  readonly label: string
}

/**
 * Produce a signed request.
 *
 * Deliberately permissive: almost every field can be omitted or set to a wrong
 * value, because the verifier's failure paths need exercising far more than its
 * happy path does.
 */
export async function signRequest(options: SignRequestOptions): Promise<SignedRequest> {
  const {
    key,
    method = 'GET',
    scheme = 'https',
    authority = 'example.com',
    path = '/',
    query = '',
    label = 'sig1',
    created = Math.floor(Date.now() / 1000),
  } = options
  const expires = options.expires ?? created + 60
  const signatureAgent =
    options.signatureAgent === undefined ? 'https://agent.example' : options.signatureAgent

  const headers: Record<string, string> = { ...options.headers }
  if (signatureAgent !== null) {
    headers['signature-agent'] = `"${signatureAgent}"`
  }

  const componentIds =
    options.components ??
    (signatureAgent === null ? ['"@authority"'] : ['"@authority"', '"signature-agent"'])
  const components = componentIds.map((id) => parseItem(id))

  const params = new Map<string, sfv.BareItem>()
  params.set('created', sf.integer(created))
  params.set('expires', sf.integer(expires))
  const keyid = options.keyid === undefined ? key.keyid : options.keyid
  if (keyid !== null) params.set('keyid', sf.string(keyid))
  const alg = options.alg === undefined ? 'ed25519' : options.alg
  if (alg !== null) params.set('alg', sf.string(alg))
  const tag = options.tag === undefined ? 'web-bot-auth' : options.tag
  if (tag !== null) params.set('tag', sf.string(tag))
  if (options.nonce !== undefined) params.set('nonce', sf.string(options.nonce))

  const signatureParamsSource = serializeInnerList(sf.innerList(components, params))

  const unsigned = createRequest({ method, scheme, authority, path, query, headers })
  const base = buildSignatureBase({ request: unsigned, components, signatureParamsSource })

  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: 'Ed25519' }, key.privateKey, new TextEncoder().encode(base)),
  )
  if (options.tamperSignature === true) signature[0] = (signature[0] ?? 0) ^ 0xff

  headers['signature-input'] = `${label}=${signatureParamsSource}`
  headers['signature'] = `${label}=:${Buffer.from(signature).toString('base64')}:`

  return {
    request: createRequest({ method, scheme, authority, path, query, headers }),
    headers,
    base,
    label,
  }
}
