import type { ReasonCode } from './reasons.js'
import { serializeItem } from './sfv/serialize.js'
import type { Item } from './sfv/types.js'
import type { NormalizedRequest } from './types.js'

/**
 * Thrown when the signature base cannot be reconstructed.
 *
 * The attached reason code carries the distinction that matters: a component
 * the caller signed but did not send is *their* mistake (`malformed`), while a
 * legitimate RFC 9421 feature Badge has not implemented is *ours*
 * (`unverifiable`). Guessing at a base we cannot build would produce
 * `signature_invalid` — a hostile-looking verdict for our own gap.
 */
export class SignatureBaseError extends Error {
  override readonly name = 'SignatureBaseError'
  constructor(
    message: string,
    readonly reason: ReasonCode,
  ) {
    super(message)
  }
}

/**
 * Component parameters defined by RFC 9421 that Badge does not implement in v0.
 *
 * `sf` and `bs` need a per-field type registry to canonicalize correctly, and
 * `req` and `tr` only apply to response signatures. Web Bot Auth's minimum
 * covered set (`@authority`, `signature-agent`) needs none of them.
 */
const UNIMPLEMENTED_PARAMS = new Set(['sf', 'bs', 'key', 'req', 'tr'])

/** Derived components that only exist for responses. */
const RESPONSE_ONLY = new Set(['@status'])

export interface SignatureBaseInput {
  readonly request: NormalizedRequest
  /** Covered component identifiers, in the order the signer listed them. */
  readonly components: readonly Item[]
  /**
   * The received bytes of the `Signature-Input` dictionary member, used
   * verbatim as the `@signature-params` value. See `DictionaryEntry.source`.
   */
  readonly signatureParamsSource: string
}

/**
 * Build the RFC 9421 §2.5 signature base.
 *
 * The result is the concatenation of one line per covered component, each
 * terminated by LF, followed by the `@signature-params` line with **no**
 * trailing LF.
 */
export function buildSignatureBase(input: SignatureBaseInput): string {
  const lines: string[] = []
  const seen = new Set<string>()

  for (const component of input.components) {
    if (component.value.type !== 'string') {
      throw new SignatureBaseError(
        'component identifiers must be strings',
        'signature_input_malformed',
      )
    }
    const name = component.value.value
    if (name !== name.toLowerCase()) {
      throw new SignatureBaseError(
        `component identifier must be lowercase: ${name}`,
        'signature_input_malformed',
      )
    }
    for (const param of component.params.keys()) {
      if (UNIMPLEMENTED_PARAMS.has(param)) {
        throw new SignatureBaseError(
          `component parameter ";${param}" is not implemented`,
          'unsupported_component',
        )
      }
    }

    const identifier = serializeItem(component)
    // RFC 9421 §2.5: a component identifier, including its parameters, may
    // appear at most once. Duplicates would let a signer's base and ours
    // diverge in ways that are hard to see.
    if (seen.has(identifier)) {
      throw new SignatureBaseError(
        `duplicate covered component: ${identifier}`,
        'signature_input_malformed',
      )
    }
    seen.add(identifier)

    lines.push(`${identifier}: ${componentValue(name, component, input.request)}`)
  }

  lines.push(`"@signature-params": ${input.signatureParamsSource}`)
  return lines.join('\n')
}

function componentValue(name: string, component: Item, request: NormalizedRequest): string {
  if (!name.startsWith('@')) return fieldValue(name, request)
  if (RESPONSE_ONLY.has(name)) {
    throw new SignatureBaseError(
      `${name} is only valid for response signatures`,
      'unsupported_component',
    )
  }
  switch (name) {
    case '@method':
      return request.method.toUpperCase()
    case '@authority':
      return normalizeAuthority(request.authority, request.scheme)
    case '@scheme':
      return request.scheme
    case '@path':
      return request.path === '' ? '/' : request.path
    case '@query':
      return `?${request.query}`
    case '@request-target':
      return request.query === '' ? request.path : `${request.path}?${request.query}`
    case '@target-uri':
      return targetUri(request)
    case '@query-param':
      return queryParam(component, request)
    default:
      throw new SignatureBaseError(`unknown derived component: ${name}`, 'unsupported_component')
  }
}

function fieldValue(name: string, request: NormalizedRequest): string {
  const value = request.header(name)
  if (value === undefined) {
    throw new SignatureBaseError(
      `covered field is not present in the request: ${name}`,
      'covered_component_missing',
    )
  }
  // RFC 9421 §2.1: strip leading and trailing OWS and collapse obs-folds. The
  // adapter is responsible for comma-joining repeated fields in order.
  return value.replace(/\r?\n[ \t]+/g, ' ').trim()
}

/**
 * RFC 9421 §2.2.3: lowercase, with the default port for the scheme omitted.
 *
 * Getting this wrong is the classic reverse-proxy failure: the signer signed
 * `example.com` and the origin sees `example.com:8080`.
 */
function normalizeAuthority(authority: string, scheme: 'http' | 'https'): string {
  const lower = authority.toLowerCase()
  const defaultPort = scheme === 'https' ? ':443' : ':80'
  return lower.endsWith(defaultPort) ? lower.slice(0, -defaultPort.length) : lower
}

function targetUri(request: NormalizedRequest): string {
  const authority = normalizeAuthority(request.authority, request.scheme)
  const path = request.path === '' ? '/' : request.path
  return `${request.scheme}://${authority}${path}${request.query === '' ? '' : `?${request.query}`}`
}

function queryParam(component: Item, request: NormalizedRequest): string {
  const nameParam = component.params.get('name')
  if (nameParam?.type !== 'string') {
    throw new SignatureBaseError(
      '@query-param requires a ;name="..." parameter',
      'signature_input_malformed',
    )
  }
  const target = nameParam.value
  const matches: string[] = []
  for (const pair of request.query.split('&')) {
    if (pair === '') continue
    const eq = pair.indexOf('=')
    const rawName = eq === -1 ? pair : pair.slice(0, eq)
    const rawValue = eq === -1 ? '' : pair.slice(eq + 1)
    if (rawName === target) matches.push(rawValue)
  }
  if (matches.length === 0) {
    throw new SignatureBaseError(
      `covered query parameter is not present: ${target}`,
      'covered_component_missing',
    )
  }
  // RFC 9421 §2.2.8 leaves repeated parameters ambiguous enough that two
  // implementations can disagree. Refusing is the only option that cannot
  // silently verify a base the signer did not produce.
  if (matches.length > 1) {
    throw new SignatureBaseError(
      `query parameter appears more than once: ${target}`,
      'unsupported_component',
    )
  }
  return decodeURIComponent((matches[0] as string).replace(/\+/g, ' '))
}
