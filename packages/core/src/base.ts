import type { ReasonCode } from './reasons.js'
import { parseDictionary, parseItem, parseList } from './sfv/parse.js'
import {
  serializeDictionary,
  serializeItem,
  serializeList,
  serializeMember,
} from './sfv/serialize.js'
import type { Item, Member } from './sfv/types.js'
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
 * Component parameters Badge still does not implement.
 *
 * `req` binds a response signature to its request and `tr` covers trailers;
 * neither has meaning when verifying a request, which is all Badge does.
 */
const UNIMPLEMENTED_PARAMS = new Set(['req', 'tr'])

/** How a structured field is typed, so `;sf` and `;key` can canonicalize it. */
export type StructuredFieldType = 'dictionary' | 'list' | 'item'

/**
 * Field types Badge is confident about.
 *
 * Deliberately short. Canonicalizing a field under the wrong type produces a
 * different base and therefore a `signature_invalid` verdict — a well-behaved
 * caller reported as hostile. A field that is not listed reports
 * `unsupported_component` instead, which is honest, and operators can extend
 * the map for fields they know.
 */
export const DEFAULT_STRUCTURED_FIELDS: Readonly<Record<string, StructuredFieldType>> = {
  accept: 'list',
  'accept-encoding': 'list',
  'accept-language': 'list',
  'cache-control': 'dictionary',
  'content-digest': 'dictionary',
  'content-length': 'item',
  'content-type': 'item',
  signature: 'dictionary',
  'signature-input': 'dictionary',
}

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
  /** Overrides and additions to {@link DEFAULT_STRUCTURED_FIELDS}. */
  readonly structuredFieldTypes?: Readonly<Record<string, StructuredFieldType>>
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
  // Merged once per request rather than once per covered component: the inputs
  // are fixed for the life of the verifier and this is the hot path.
  const types: Readonly<Record<string, StructuredFieldType>> =
    input.structuredFieldTypes === undefined
      ? DEFAULT_STRUCTURED_FIELDS
      : { ...DEFAULT_STRUCTURED_FIELDS, ...input.structuredFieldTypes }

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

    lines.push(`${identifier}: ${componentValue(name, component, input.request, types)}`)
  }

  lines.push(`"@signature-params": ${input.signatureParamsSource}`)
  return lines.join('\n')
}

function componentValue(
  name: string,
  component: Item,
  request: NormalizedRequest,
  types: Readonly<Record<string, StructuredFieldType>>,
): string {
  if (!name.startsWith('@')) return fieldComponent(name, component, request, types)
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

/**
 * Whether a boolean component parameter is actually set.
 *
 * `params.has()` is not enough: RFC 9651 lets a signer write `;sf=?0`, which
 * means the flag is off. Treating it as on would canonicalize a field the
 * signer left raw, and the resulting base would differ by a few bytes — a
 * well-behaved signer reported as `signature_invalid`.
 */
function flagSet(component: Item, name: string): boolean {
  const value = component.params.get(name)
  if (value === undefined) return false
  if (value.type !== 'boolean') {
    throw new SignatureBaseError(`;${name} must be a boolean`, 'signature_input_malformed')
  }
  return value.value
}

function fieldComponent(
  name: string,
  component: Item,
  request: NormalizedRequest,
  types: Readonly<Record<string, StructuredFieldType>>,
): string {
  const bs = flagSet(component, 'bs')
  const sf = flagSet(component, 'sf')
  const keyParam = component.params.get('key')

  if (keyParam !== undefined && keyParam.type !== 'string') {
    throw new SignatureBaseError(';key must be a string', 'signature_input_malformed')
  }
  if (bs && (sf || keyParam !== undefined)) {
    // RFC 9421 §2.1.3: ;bs is mutually exclusive with the parsing parameters.
    throw new SignatureBaseError(
      ';bs cannot be combined with ;sf or ;key',
      'signature_input_malformed',
    )
  }

  if (bs) return byteSequenceValue(name, request)
  if (sf || keyParam !== undefined) {
    return structuredValue(
      name,
      request,
      types,
      keyParam?.type === 'string' ? keyParam.value : undefined,
    )
  }
  return fieldValue(name, request)
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

/** RFC 9421 §2.1.3: each field value becomes its own Byte Sequence, combined as a List. */
function byteSequenceValue(name: string, request: NormalizedRequest): string {
  if (request.headerValues === undefined) {
    throw new SignatureBaseError(
      ';bs needs the individual field values, which this adapter does not expose',
      'unsupported_component',
    )
  }
  const values = request.headerValues(name)
  if (values === undefined || values.length === 0) {
    throw new SignatureBaseError(
      `covered field is not present in the request: ${name}`,
      'covered_component_missing',
    )
  }
  return values
    .map((value) => `:${base64OfFieldValue(value.replace(/\r?\n[ \t]+/g, ' ').trim())}:`)
    .join(', ')
}

/**
 * Base64 of a field value's own bytes.
 *
 * Uses `btoa` rather than Node's `Buffer` for two reasons. Core targets Deno,
 * Bun and Workers as well as Node, and `Buffer` is not defined there — a `;bs`
 * component would have thrown `ReferenceError` and surfaced as
 * `internal_error`. And Node hands header values over already decoded as
 * latin1, one character per wire byte, so re-encoding them as UTF-8 turns byte
 * 0xE9 into 0xC3 0xA9 and produces a base that disagrees with a correct signer.
 * `btoa` maps character codes 0–255 straight back to those bytes.
 */
function base64OfFieldValue(value: string): string {
  for (let i = 0; i < value.length; i += 1) {
    if (value.charCodeAt(i) > 0xff) {
      throw new SignatureBaseError(
        'field value carries characters outside the byte range, so its wire bytes cannot be recovered',
        'unsupported_component',
      )
    }
  }
  return btoa(value)
}

/** RFC 9421 §2.1.1 (`;sf`) and §2.1.2 (`;key`): re-serialize the field strictly. */
function structuredValue(
  name: string,
  request: NormalizedRequest,
  types: Readonly<Record<string, StructuredFieldType>>,
  key: string | undefined,
): string {
  const raw = fieldValue(name, request)
  // ;key only has meaning for a Dictionary, so it settles the type by itself.
  // `Object.hasOwn` rather than a plain lookup: a header literally named
  // `constructor` or `__proto__` would otherwise resolve through the prototype
  // chain to a truthy value and slip past the unknown-type guard.
  const type =
    key !== undefined ? 'dictionary' : Object.hasOwn(types, name) ? types[name] : undefined
  if (type === undefined) {
    throw new SignatureBaseError(
      `no structured field type is known for "${name}", so ;sf cannot canonicalize it`,
      'unsupported_component',
    )
  }

  try {
    if (type === 'dictionary') {
      const dict = parseDictionary(raw)
      if (key === undefined) {
        const members = new Map<string, Member>()
        for (const [memberKey, entry] of dict) members.set(memberKey, entry.value)
        return serializeDictionary(members)
      }
      const entry = dict.get(key)
      if (entry === undefined) {
        throw new SignatureBaseError(
          `covered dictionary key is not present in ${name}: ${key}`,
          'covered_component_missing',
        )
      }
      return serializeMember(entry.value)
    }
    if (type === 'list') return serializeList(parseList(raw))
    return serializeItem(parseItem(raw))
  } catch (err) {
    if (err instanceof SignatureBaseError) throw err
    throw new SignatureBaseError(
      `covered field ${name} is not a valid structured field`,
      'covered_field_not_structured',
    )
  }
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
