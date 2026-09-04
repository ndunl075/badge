/**
 * RFC 9651 Structured Field Values.
 *
 * Bare items are tagged rather than represented by bare JS values, because the
 * distinction Badge cares about most — a Token vs. a String — is invisible
 * otherwise. `tag="web-bot-auth"` is a String; `alg=ed25519` would be a Token.
 * Collapsing them would let a caller smuggle one past a check for the other.
 */
export type BareItem =
  | { readonly type: 'integer'; readonly value: number }
  | { readonly type: 'decimal'; readonly value: number }
  | { readonly type: 'string'; readonly value: string }
  | { readonly type: 'token'; readonly value: string }
  | { readonly type: 'binary'; readonly value: Uint8Array }
  | { readonly type: 'boolean'; readonly value: boolean }
  /** RFC 9651 §3.3.7, `@1659578233`. */
  | { readonly type: 'date'; readonly value: number }
  /** RFC 9651 §3.3.8, `%"caf%c3%a9"`. */
  | { readonly type: 'displaystring'; readonly value: string }

/** Ordered, per RFC 9651 — parameter order is preserved and is signature-relevant. */
export type Parameters = ReadonlyMap<string, BareItem>

export interface Item {
  readonly kind: 'item'
  readonly value: BareItem
  readonly params: Parameters
}

export interface InnerList {
  readonly kind: 'inner-list'
  readonly items: readonly Item[]
  readonly params: Parameters
}

export type Member = Item | InnerList

export interface DictionaryEntry {
  readonly value: Member
  /**
   * The exact received bytes of this member, from the first character of the
   * value through the last character of its parameters, excluding surrounding
   * whitespace and the separating comma.
   *
   * This exists for RFC 9421 `@signature-params`. The signer computed its
   * signature base from *its own* serialization of the parameters; if we
   * re-serialize from the parse tree and our spacing or number formatting
   * differs by one byte, the base differs and every signature fails with a
   * verdict that looks cryptographic. Slicing the received bytes sidesteps the
   * entire class of canonicalization mismatch.
   */
  readonly source: string
}

export type Dictionary = ReadonlyMap<string, DictionaryEntry>

export class SfParseError extends Error {
  override readonly name = 'SfParseError'
  constructor(
    message: string,
    readonly position: number,
  ) {
    super(`${message} (at offset ${position})`)
  }
}
