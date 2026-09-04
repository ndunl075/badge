import {
  SfParseError,
  type BareItem,
  type Dictionary,
  type DictionaryEntry,
  type InnerList,
  type Item,
  type Member,
  type Parameters,
} from './types.js'

/**
 * A parser for RFC 9651 Structured Field Values, implementing the algorithms in
 * §4.2 literally.
 *
 * "Literally" is the point: structured fields are the outermost attack surface
 * of a verifier, reached before any signature check. A permissive hand-rolled
 * parser that accepts what the spec rejects is how two implementations end up
 * disagreeing about what was signed.
 */
class Parser {
  private i = 0

  constructor(private readonly s: string) {}

  get position(): number {
    return this.i
  }

  private fail(message: string): never {
    throw new SfParseError(message, this.i)
  }

  private peek(): string | undefined {
    return this.s[this.i]
  }

  private eof(): boolean {
    return this.i >= this.s.length
  }

  private take(): string {
    const c = this.s[this.i]
    if (c === undefined) this.fail('unexpected end of input')
    this.i += 1
    return c
  }

  private expect(c: string): void {
    if (this.peek() !== c) this.fail(`expected ${JSON.stringify(c)}`)
    this.i += 1
  }

  /** SP only, per the "discard leading SP characters" steps. */
  private skipSp(): void {
    while (this.s[this.i] === ' ') this.i += 1
  }

  /** OWS = SP / HTAB, used around list and dictionary separators. */
  private skipOws(): void {
    while (this.s[this.i] === ' ' || this.s[this.i] === '\t') this.i += 1
  }

  // -- entry points ---------------------------------------------------------

  parseDictionary(): Dictionary {
    const dict = new Map<string, DictionaryEntry>()
    this.skipSp()
    while (!this.eof()) {
      const key = this.parseKey()
      let entry: DictionaryEntry
      if (this.peek() === '=') {
        this.i += 1
        const start = this.i
        const value = this.parseItemOrInnerList()
        entry = { value, source: this.s.slice(start, this.i) }
      } else {
        const start = this.i
        const params = this.parseParameters()
        const value: Item = { kind: 'item', value: { type: 'boolean', value: true }, params }
        entry = { value, source: this.s.slice(start, this.i) }
      }
      // Later duplicates replace earlier ones (RFC 9651 §4.2.2 step 2.4).
      dict.delete(key)
      dict.set(key, entry)
      this.skipOws()
      if (this.eof()) return dict
      this.expect(',')
      this.skipOws()
      if (this.eof()) this.fail('trailing comma in dictionary')
    }
    return dict
  }

  parseList(): Member[] {
    const members: Member[] = []
    this.skipSp()
    while (!this.eof()) {
      members.push(this.parseItemOrInnerList())
      this.skipOws()
      if (this.eof()) return members
      this.expect(',')
      this.skipOws()
      if (this.eof()) this.fail('trailing comma in list')
    }
    return members
  }

  parseItem(): Item {
    this.skipSp()
    const value = this.parseBareItem()
    const params = this.parseParameters()
    this.skipSp()
    return { kind: 'item', value, params }
  }

  assertConsumed(): void {
    this.skipSp()
    if (!this.eof()) this.fail('unexpected trailing characters')
  }

  // -- grammar --------------------------------------------------------------

  private parseItemOrInnerList(): Member {
    return this.peek() === '(' ? this.parseInnerList() : this.parseBareItemWithParams()
  }

  private parseBareItemWithParams(): Item {
    const value = this.parseBareItem()
    const params = this.parseParameters()
    return { kind: 'item', value, params }
  }

  private parseInnerList(): InnerList {
    this.expect('(')
    const items: Item[] = []
    for (;;) {
      this.skipSp()
      if (this.peek() === ')') {
        this.i += 1
        return { kind: 'inner-list', items, params: this.parseParameters() }
      }
      items.push(this.parseBareItemWithParams())
      const next = this.peek()
      if (next !== ' ' && next !== ')') this.fail('expected SP or ")" in inner list')
    }
  }

  private parseParameters(): Parameters {
    const params = new Map<string, BareItem>()
    while (this.peek() === ';') {
      this.i += 1
      this.skipSp()
      const key = this.parseKey()
      let value: BareItem = { type: 'boolean', value: true }
      if (this.peek() === '=') {
        this.i += 1
        value = this.parseBareItem()
      }
      params.delete(key)
      params.set(key, value)
    }
    return params
  }

  private parseKey(): string {
    const first = this.peek()
    if (first === undefined || !(isLcAlpha(first) || first === '*')) {
      this.fail('expected a key')
    }
    const start = this.i
    this.i += 1
    while (!this.eof()) {
      const c = this.s[this.i] as string
      if (isLcAlpha(c) || isDigit(c) || c === '_' || c === '-' || c === '.' || c === '*') {
        this.i += 1
      } else break
    }
    return this.s.slice(start, this.i)
  }

  private parseBareItem(): BareItem {
    const c = this.peek()
    if (c === undefined) this.fail('expected a bare item')
    if (c === '-' || isDigit(c)) return this.parseNumber()
    if (c === '"') return { type: 'string', value: this.parseString() }
    if (c === ':') return { type: 'binary', value: this.parseByteSequence() }
    if (c === '?') return { type: 'boolean', value: this.parseBoolean() }
    if (c === '@') return { type: 'date', value: this.parseDate() }
    if (c === '%') return { type: 'displaystring', value: this.parseDisplayString() }
    if (c === '*' || isAlpha(c)) return { type: 'token', value: this.parseToken() }
    this.fail(`unrecognized bare item starting with ${JSON.stringify(c)}`)
  }

  private parseNumber(): BareItem {
    let sign = 1
    if (this.peek() === '-') {
      this.i += 1
      sign = -1
    }
    const c = this.peek()
    if (c === undefined || !isDigit(c)) this.fail('expected a digit')
    let digits = ''
    let isDecimal = false
    while (!this.eof()) {
      const ch = this.s[this.i] as string
      if (isDigit(ch)) {
        digits += ch
        this.i += 1
      } else if (!isDecimal && ch === '.') {
        if (digits.length > 12) this.fail('too many digits before the decimal point')
        digits += ch
        isDecimal = true
        this.i += 1
      } else break
      if (!isDecimal && digits.length > 15) this.fail('integer too long')
      if (isDecimal && digits.length > 16) this.fail('decimal too long')
    }
    if (!isDecimal) return { type: 'integer', value: sign * Number(digits) }
    const dot = digits.indexOf('.')
    if (dot === digits.length - 1) this.fail('decimal must have digits after the point')
    if (digits.length - dot - 1 > 3) this.fail('at most three fractional digits')
    return { type: 'decimal', value: sign * Number(digits) }
  }

  private parseString(): string {
    this.expect('"')
    let out = ''
    while (!this.eof()) {
      const c = this.take()
      if (c === '\\') {
        const next = this.take()
        if (next !== '"' && next !== '\\') this.fail('invalid string escape')
        out += next
      } else if (c === '"') {
        return out
      } else if (!isPrintableAscii(c)) {
        this.fail('invalid character in string')
      } else {
        out += c
      }
    }
    this.fail('unterminated string')
  }

  private parseToken(): string {
    const first = this.peek()
    if (first === undefined || !(isAlpha(first) || first === '*')) this.fail('expected a token')
    const start = this.i
    this.i += 1
    while (!this.eof()) {
      const c = this.s[this.i] as string
      if (isTchar(c) || c === ':' || c === '/') this.i += 1
      else break
    }
    return this.s.slice(start, this.i)
  }

  private parseByteSequence(): Uint8Array {
    this.expect(':')
    const end = this.s.indexOf(':', this.i)
    if (end === -1) this.fail('unterminated byte sequence')
    const b64 = this.s.slice(this.i, end)
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) this.fail('invalid base64 in byte sequence')
    this.i = end + 1
    try {
      const bin = atob(b64)
      const bytes = new Uint8Array(bin.length)
      for (let n = 0; n < bin.length; n += 1) bytes[n] = bin.charCodeAt(n)
      return bytes
    } catch {
      this.fail('invalid base64 in byte sequence')
    }
  }

  private parseBoolean(): boolean {
    this.expect('?')
    const c = this.take()
    if (c === '1') return true
    if (c === '0') return false
    this.fail('expected ?0 or ?1')
  }

  private parseDate(): number {
    this.expect('@')
    const n = this.parseNumber()
    if (n.type !== 'integer') this.fail('date must be an integer')
    return n.value
  }

  private parseDisplayString(): string {
    this.expect('%')
    this.expect('"')
    const bytes: number[] = []
    while (!this.eof()) {
      const c = this.take()
      if (c === '%') {
        const hex = this.s.slice(this.i, this.i + 2)
        if (!/^[0-9a-f]{2}$/.test(hex)) this.fail('invalid percent escape in display string')
        this.i += 2
        bytes.push(Number.parseInt(hex, 16))
      } else if (c === '"') {
        try {
          return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes))
        } catch {
          this.fail('display string is not valid UTF-8')
        }
      } else if (c === '\\' || !isPrintableAscii(c)) {
        this.fail('invalid character in display string')
      } else {
        bytes.push(c.charCodeAt(0))
      }
    }
    this.fail('unterminated display string')
  }
}

function isDigit(c: string): boolean {
  return c >= '0' && c <= '9'
}
function isLcAlpha(c: string): boolean {
  return c >= 'a' && c <= 'z'
}
function isAlpha(c: string): boolean {
  return isLcAlpha(c) || (c >= 'A' && c <= 'Z')
}
function isPrintableAscii(c: string): boolean {
  const code = c.charCodeAt(0)
  return code >= 0x20 && code <= 0x7e
}
function isTchar(c: string): boolean {
  return isAlpha(c) || isDigit(c) || "!#$%&'*+-.^_`|~".includes(c)
}

/** Parse a Dictionary field value (RFC 9651 §3.2), such as `Signature-Input`. */
export function parseDictionary(input: string): Dictionary {
  const p = new Parser(input)
  const dict = p.parseDictionary()
  p.assertConsumed()
  return dict
}

/** Parse a List field value (RFC 9651 §3.1). */
export function parseList(input: string): Member[] {
  const p = new Parser(input)
  const list = p.parseList()
  p.assertConsumed()
  return list
}

/** Parse an Item field value (RFC 9651 §3.3), such as `Signature-Agent`. */
export function parseItem(input: string): Item {
  const p = new Parser(input)
  const item = p.parseItem()
  p.assertConsumed()
  return item
}
