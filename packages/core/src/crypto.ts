/**
 * Key handling: RFC 7638 JWK thumbprints and Ed25519 verification.
 *
 * Everything here runs on WebCrypto, so the same code works on Node, Deno, Bun,
 * and Workers without a native dependency.
 */
import type { webcrypto } from 'node:crypto'

/**
 * An imported public key.
 *
 * Aliased from the Node typings rather than pulling the DOM lib in, which would
 * put `window` and `document` into the type space of a server-side library. The
 * import is type-only and erases completely, so nothing here binds to Node at
 * runtime.
 */
export type PublicKey = webcrypto.CryptoKey

/** A JWK as it appears in a key directory, plus the validity window the Web Bot Auth directory draft adds. */
export interface Jwk {
  readonly kty: string
  readonly crv?: string
  readonly x?: string
  readonly y?: string
  readonly n?: string
  readonly e?: string
  readonly k?: string
  readonly kid?: string
  readonly alg?: string
  readonly use?: string
  readonly key_ops?: readonly string[]
  /** Not valid before, Unix seconds. */
  readonly nbf?: number
  /** Not valid after, Unix seconds. */
  readonly exp?: number
}

export class KeyError extends Error {
  override readonly name = 'KeyError'
}

/** The members RFC 7638 §3.2 includes in the thumbprint, in lexicographic order. */
const THUMBPRINT_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  EC: ['crv', 'kty', 'x', 'y'],
  OKP: ['crv', 'kty', 'x'],
  RSA: ['e', 'kty', 'n'],
  oct: ['k', 'kty'],
}

/**
 * The RFC 7638 canonical form: required members only, lexicographically
 * ordered, no whitespace.
 *
 * Exported because it is the part worth pinning in a test. A thumbprint that
 * disagrees with every other implementation by one byte of JSON is a
 * `key_not_found` verdict that nobody can debug from the outside.
 */
export function canonicalJwkJson(jwk: Jwk): string {
  const members = THUMBPRINT_MEMBERS[jwk.kty]
  if (members === undefined) throw new KeyError(`unsupported key type: ${jwk.kty}`)
  const parts: string[] = []
  for (const member of members) {
    const value = (jwk as unknown as Record<string, unknown>)[member]
    if (typeof value !== 'string' || value === '') {
      throw new KeyError(`key is missing required member "${member}"`)
    }
    parts.push(`${JSON.stringify(member)}:${JSON.stringify(value)}`)
  }
  return `{${parts.join(',')}}`
}

/**
 * RFC 7638 JWK thumbprint, base64url with no padding.
 *
 * This is the `keyid` a Web Bot Auth signer puts in `Signature-Input`. Badge
 * always computes it locally rather than trusting a directory's own `kid`:
 * accepting the directory's label would let one key in a directory impersonate
 * another key in the same directory.
 */
export async function jwkThumbprint(jwk: Jwk): Promise<string> {
  const json = new TextEncoder().encode(canonicalJwkJson(jwk))
  const digest = await crypto.subtle.digest('SHA-256', json)
  return base64UrlEncode(new Uint8Array(digest))
}

/**
 * Members a public JWK may carry. Everything else is dropped.
 *
 * A whitelist rather than a blacklist, for the same reason publishing refuses
 * private members by name: deleting `d` from an exported private key leaves
 * `key_ops: ["sign"]` and `ext: true` behind, which is a public key advertising
 * that it can sign. Enumerating what may be published cannot fail that way.
 */
const PUBLIC_MEMBERS = [
  'kty',
  'crv',
  'x',
  'y',
  'n',
  'e',
  'kid',
  'alg',
  'use',
  'nbf',
  'exp',
] as const

/** Reduce any JWK to the public members a key directory should carry. */
export function toPublicJwk(jwk: Jwk): Jwk {
  const source = jwk as unknown as Record<string, unknown>
  const out: Record<string, unknown> = {}
  for (const member of PUBLIC_MEMBERS) {
    if (source[member] !== undefined) out[member] = source[member]
  }
  return out as unknown as Jwk
}

export function isEd25519(jwk: Jwk): boolean {
  return jwk.kty === 'OKP' && jwk.crv === 'Ed25519'
}

export async function importEd25519PublicKey(jwk: Jwk): Promise<PublicKey> {
  if (!isEd25519(jwk)) throw new KeyError('not an Ed25519 key')
  if (typeof jwk.x !== 'string' || jwk.x === '') throw new KeyError('key is missing "x"')
  return crypto.subtle.importKey(
    'jwk',
    { kty: 'OKP', crv: 'Ed25519', x: jwk.x },
    { name: 'Ed25519' },
    false,
    ['verify'],
  )
}

export async function verifyEd25519(
  key: PublicKey,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  // A malformed signature makes WebCrypto throw in some runtimes and return
  // false in others. Both mean the same thing here: not verified.
  try {
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, data)
  } catch {
    return false
  }
}

/** Whether a directory key's `nbf`/`exp` window contains `now` (Unix seconds). */
export function keyValidityAt(jwk: Jwk, now: number): 'valid' | 'not-yet-valid' | 'expired' {
  if (typeof jwk.nbf === 'number' && now < jwk.nbf) return 'not-yet-valid'
  if (typeof jwk.exp === 'number' && now >= jwk.exp) return 'expired'
  return 'valid'
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function base64UrlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new KeyError('invalid base64url')
  const padded = value.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='))
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i)
  return bytes
}
