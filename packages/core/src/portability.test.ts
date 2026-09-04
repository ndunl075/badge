import { readdirSync, readFileSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * ARCHITECTURE.md §5 says core runs on Node, Deno, Bun and Workers on one
 * WebCrypto path. A review pass found a `Buffer` call in `;bs` canonicalization
 * that would have thrown `ReferenceError` everywhere but Node and surfaced as
 * `internal_error`.
 *
 * A claim in a document does not enforce itself, so this does.
 */
const CORE_SRC = fileURLToPath(new URL('.', import.meta.url))

const sourceFiles = (dir: string): string[] =>
  readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) return sourceFiles(full)
    if (!entry.endsWith('.ts') || entry.endsWith('.test.ts')) return []
    return [full]
  })

/** Globals that exist only on Node. `node:` imports are caught separately. */
const NODE_ONLY = [
  { name: 'Buffer', pattern: /\bBuffer\s*\./ },
  { name: 'process', pattern: /\bprocess\s*\./ },
  { name: '__dirname', pattern: /\b__dirname\b/ },
  { name: 'require', pattern: /\brequire\s*\(/ },
]

describe('core stays runtime-agnostic', () => {
  const files = sourceFiles(CORE_SRC)

  it('finds the sources it is meant to check', () => {
    expect(files.length).toBeGreaterThan(5)
  })

  it.each(NODE_ONLY)('uses no $name', ({ pattern }) => {
    const offenders = files.filter((file) => {
      const source = readFileSync(file, 'utf8')
      // Ignore comments: the fix for the original finding explains itself.
      const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
      return pattern.test(code)
    })
    expect(offenders).toEqual([])
  })

  it('imports nothing from node: except as a type', () => {
    for (const file of files) {
      const source = readFileSync(file, 'utf8')
      for (const match of source.matchAll(/^import\s+(type\s+)?.*?from\s+'node:.*$/gm)) {
        // A type-only import erases at build time, so it binds nothing at runtime.
        expect(match[1], `${file}: ${match[0]}`).toBe('type ')
      }
    }
  })
})
