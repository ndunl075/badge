import { describe, expect, it } from 'vitest'
import { parseDictionary, parseItem, parseList } from './parse.js'
import { serializeItem } from './serialize.js'
import { SfParseError } from './types.js'

/**
 * Randomized robustness checks for the structured fields parsers.
 *
 * These are the outermost attack surface of the verifier, reached before any
 * signature check, on input an attacker fully controls. The Go sidecar gets
 * coverage from Go's native fuzzer; this is the equivalent for the parser that
 * actually ships to Node users.
 *
 * The property under test is not "parses correctly" — it is "fails correctly".
 * Any input at all must either parse or raise SfParseError. A TypeError or a
 * RangeError escaping the parser becomes `internal_error` at the verifier,
 * which the reason table reserves for Badge's own failures, so a caller who can
 * provoke one can manufacture Badge-fault verdicts.
 */

const ALPHABET = ` !"#$%&'()*+,-./0123456789:;<=>?@ABCZ[\\]^_\`abcz{|}~\t\n\ré\u{1f600}`

const mulberry32 = (seed: number) => () => {
  seed = (seed + 0x6d2b79f5) | 0
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296
}

/** Interesting shapes to mutate, rather than only uniform noise. */
const SEEDS = [
  'sig1=("@authority" "signature-agent");created=1735689600;expires=1735689660;keyid="abc";alg="ed25519";tag="web-bot-auth"',
  'a=1, b=2, a=3',
  'a;b;c=1',
  '("a" "b");x=1',
  '%"caf%c3%a9"',
  '@1659578233',
  ':aGVsbG8=:',
  '"escaped \\" and \\\\"',
  '4.567',
  'tok:with/slashes',
  '',
  ',',
  '(',
  ':',
  '"',
  '%',
  '?',
  '@',
  '::::',
  '%"%zz"',
  'a='.concat('9'.repeat(40)),
  'a=1, '.repeat(50),
  '('.repeat(50),
  ';a'.repeat(50),
]

const randomString = (rand: () => number, maxLength: number): string => {
  const length = Math.floor(rand() * maxLength)
  let out = ''
  for (let i = 0; i < length; i += 1) {
    out += ALPHABET[Math.floor(rand() * ALPHABET.length)] as string
  }
  return out
}

/** Mutate a seed the way a fuzzer would: splice, duplicate, truncate, corrupt. */
const mutate = (rand: () => number, seed: string): string => {
  const choice = Math.floor(rand() * 5)
  if (seed === '' || choice === 0) return randomString(rand, 60)
  const at = Math.floor(rand() * seed.length)
  switch (choice) {
    case 1:
      return seed.slice(0, at) + randomString(rand, 6) + seed.slice(at)
    case 2:
      return seed.slice(0, at)
    case 3:
      return seed + seed.slice(at)
    default:
      return (
        seed.slice(0, at) +
        (ALPHABET[Math.floor(rand() * ALPHABET.length)] as string) +
        seed.slice(at + 1)
      )
  }
}

const inputs = (count: number): string[] => {
  const rand = mulberry32(0x5eed)
  const out: string[] = [...SEEDS]
  while (out.length < count) {
    out.push(mutate(rand, SEEDS[Math.floor(rand() * SEEDS.length)] as string))
  }
  return out
}

const CASES = inputs(6000)

const expectOnlyParseErrors = (parse: (input: string) => unknown, label: string): void => {
  for (const input of CASES) {
    try {
      parse(input)
    } catch (err) {
      if (err instanceof SfParseError) continue
      throw new Error(
        `${label} threw ${(err as Error)?.constructor?.name ?? typeof err} on ${JSON.stringify(input)}: ${String(err)}`,
      )
    }
  }
}

describe('structured fields parsers survive hostile input', () => {
  it('parseDictionary raises only SfParseError', () => {
    expectOnlyParseErrors(parseDictionary, 'parseDictionary')
  })

  it('parseList raises only SfParseError', () => {
    expectOnlyParseErrors(parseList, 'parseList')
  })

  it('parseItem raises only SfParseError', () => {
    expectOnlyParseErrors(parseItem, 'parseItem')
  })

  it('reports a position within the input on every failure', () => {
    for (const input of CASES) {
      try {
        parseDictionary(input)
      } catch (err) {
        const position = (err as SfParseError).position
        expect(position).toBeGreaterThanOrEqual(0)
        expect(position).toBeLessThanOrEqual(input.length)
      }
    }
  })

  // A round trip that loses information is a way for two implementations to
  // disagree about what was signed.
  it('round trips anything it accepts, without changing the value', () => {
    for (const input of CASES) {
      let item
      try {
        item = parseItem(input)
      } catch {
        continue
      }
      let serialized: string
      try {
        serialized = serializeItem(item)
      } catch {
        // Serialization is allowed to refuse a value it cannot represent; it is
        // not allowed to produce something unparseable.
        continue
      }
      const again = parseItem(serialized)
      expect(again.value.type).toBe(item.value.type)
      expect(again.value).toEqual(item.value)
    }
  })

  it('extracts source spans that are genuinely substrings of the input', () => {
    for (const input of CASES) {
      let dict
      try {
        dict = parseDictionary(input)
      } catch {
        continue
      }
      for (const [, entry] of dict) {
        if (entry.source !== '') expect(input).toContain(entry.source)
      }
    }
  })
})
