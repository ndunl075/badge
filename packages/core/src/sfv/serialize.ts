import type { BareItem, InnerList, Item, Member, Parameters } from './types.js'

/**
 * RFC 9651 §4.1 serialization.
 *
 * Badge only serializes when it is the *signer* (the testkit, the directory
 * helper). Verification never round-trips a received field through here — see
 * the note on `DictionaryEntry.source`.
 */

export class SfSerializeError extends Error {
  override readonly name = 'SfSerializeError'
}

const MAX_INTEGER = 999_999_999_999_999
const MIN_INTEGER = -999_999_999_999_999

export function serializeBareItem(item: BareItem): string {
  switch (item.type) {
    case 'integer':
      if (!Number.isInteger(item.value)) throw new SfSerializeError('integer must be integral')
      if (item.value > MAX_INTEGER || item.value < MIN_INTEGER) {
        throw new SfSerializeError('integer out of range')
      }
      return String(item.value)
    case 'decimal':
      return serializeDecimal(item.value)
    case 'string':
      return serializeString(item.value)
    case 'token':
      if (!/^[a-zA-Z*][!#$%&'*+\-.^_`|~\w:/]*$/.test(item.value)) {
        throw new SfSerializeError(`invalid token: ${item.value}`)
      }
      return item.value
    case 'binary':
      return `:${base64(item.value)}:`
    case 'boolean':
      return item.value ? '?1' : '?0'
    case 'date':
      if (!Number.isInteger(item.value)) throw new SfSerializeError('date must be integral')
      return `@${item.value}`
    case 'displaystring':
      return serializeDisplayString(item.value)
  }
}

function serializeDecimal(value: number): string {
  if (!Number.isFinite(value)) throw new SfSerializeError('decimal must be finite')
  const rounded = Math.round(value * 1000) / 1000
  if (Math.abs(Math.trunc(rounded)).toString().length > 12) {
    throw new SfSerializeError('decimal has too many integer digits')
  }
  const text = rounded.toString()
  return text.includes('.') ? text : `${text}.0`
}

function serializeString(value: string): string {
  let out = '"'
  for (const c of value) {
    const code = c.charCodeAt(0)
    if (code < 0x20 || code > 0x7e) throw new SfSerializeError('string must be printable ASCII')
    if (c === '"' || c === '\\') out += '\\'
    out += c
  }
  return `${out}"`
}

function serializeDisplayString(value: string): string {
  let out = '%"'
  for (const byte of new TextEncoder().encode(value)) {
    if (byte === 0x25 || byte === 0x22 || byte <= 0x1f || byte >= 0x7f) {
      out += `%${byte.toString(16).padStart(2, '0')}`
    } else {
      out += String.fromCharCode(byte)
    }
  }
  return `${out}"`
}

function base64(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

export function serializeParameters(params: Parameters): string {
  let out = ''
  for (const [key, value] of params) {
    out += `;${key}`
    if (!(value.type === 'boolean' && value.value)) out += `=${serializeBareItem(value)}`
  }
  return out
}

export function serializeItem(item: Item): string {
  return serializeBareItem(item.value) + serializeParameters(item.params)
}

export function serializeInnerList(list: InnerList): string {
  const inner = list.items.map(serializeItem).join(' ')
  return `(${inner})${serializeParameters(list.params)}`
}

export function serializeMember(member: Member): string {
  return member.kind === 'item' ? serializeItem(member) : serializeInnerList(member)
}

export function serializeList(members: readonly Member[]): string {
  return members.map(serializeMember).join(', ')
}

export function serializeDictionary(dict: ReadonlyMap<string, Member>): string {
  const parts: string[] = []
  for (const [key, member] of dict) {
    if (member.kind === 'item' && member.value.type === 'boolean' && member.value.value) {
      parts.push(key + serializeParameters(member.params))
    } else {
      parts.push(`${key}=${serializeMember(member)}`)
    }
  }
  return parts.join(', ')
}

// -- convenience constructors, used heavily by the signer and tests ----------

export const sf = {
  integer: (value: number): BareItem => ({ type: 'integer', value }),
  decimal: (value: number): BareItem => ({ type: 'decimal', value }),
  string: (value: string): BareItem => ({ type: 'string', value }),
  token: (value: string): BareItem => ({ type: 'token', value }),
  binary: (value: Uint8Array): BareItem => ({ type: 'binary', value }),
  boolean: (value: boolean): BareItem => ({ type: 'boolean', value }),
  date: (value: number): BareItem => ({ type: 'date', value }),
  displayString: (value: string): BareItem => ({ type: 'displaystring', value }),
  item: (value: BareItem, params: Parameters = new Map()): Item => ({
    kind: 'item',
    value,
    params,
  }),
  innerList: (items: readonly Item[], params: Parameters = new Map()): InnerList => ({
    kind: 'inner-list',
    items,
    params,
  }),
} as const
