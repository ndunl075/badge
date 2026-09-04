import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateSigningKey, signRequest, type SigningKey } from '@badge/testkit'
import { beforeAll, describe, expect, it } from 'vitest'
import { run } from './cli.js'
import { EXIT_FAILED, EXIT_OK, EXIT_USAGE, type Io } from './io.js'

let dir: string
let key: SigningKey

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'badge-cli-'))
  key = await generateSigningKey()
})

interface Captured {
  code: number
  out: string
  err: string
}

const invoke = async (...argv: string[]): Promise<Captured> => {
  const out: string[] = []
  const err: string[] = []
  const io: Io = { out: (t) => out.push(t), err: (t) => err.push(t) }
  const code = await run(argv, io)
  return { code, out: out.join('\n'), err: err.join('\n') }
}

const headerArgs = (headers: Record<string, string>): string[] =>
  Object.entries(headers).flatMap(([name, value]) => ['--header', `${name}: ${value}`])

describe('badge (top level)', () => {
  it('prints help with no arguments', async () => {
    const result = await invoke()
    expect(result.code).toBe(EXIT_OK)
    expect(result.out).toContain('badge verify')
  })

  it('reports an unknown command as a usage error', async () => {
    const result = await invoke('nonsense')
    expect(result.code).toBe(EXIT_USAGE)
    expect(result.err).toContain('unknown command')
  })

  it('reports a missing required flag as a usage error, not a crash', async () => {
    expect((await invoke('verify')).code).toBe(EXIT_USAGE)
  })
})

describe('badge keygen', () => {
  it('writes a private key and prints only the public half', async () => {
    const file = join(dir, 'key.json')
    const result = await invoke('keygen', '--out', file)
    expect(result.code).toBe(EXIT_OK)

    const printed = JSON.parse(result.out) as { keyid: string; publicJwk: Record<string, unknown> }
    expect(printed.keyid).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(printed.publicJwk).toEqual({ kty: 'OKP', crv: 'Ed25519', x: expect.any(String) })
    expect(result.out).not.toContain('"d"')

    const stored = JSON.parse(await readFile(file, 'utf8')) as { d?: string }
    expect(stored.d).toBeTypeOf('string')
    expect(result.err).toContain('do not publish')
  })

  it('carries a rotation window into the public key', async () => {
    const result = await invoke('keygen', '--nbf', '100', '--exp', '200')
    const printed = JSON.parse(result.out) as { publicJwk: { nbf: number; exp: number } }
    expect(printed.publicJwk).toMatchObject({ nbf: 100, exp: 200 })
  })

  // WebCrypto exports alg: "Ed25519", which is neither the JWA name nor the
  // HTTP Message Signatures registry name, and a wrong alg in a published
  // directory is worse than no alg at all.
  it('writes a minimal key with no WebCrypto bookkeeping', async () => {
    const file = join(dir, 'minimal.json')
    await invoke('keygen', '--out', file)
    const stored = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>
    expect(Object.keys(stored).sort()).toEqual(['crv', 'd', 'kid', 'kty', 'x'])
  })
})

describe('badge directory build', () => {
  it('builds a JWKS from a private key file without leaking it', async () => {
    const file = join(dir, 'build.json')
    await invoke('keygen', '--out', file)
    const result = await invoke('directory', 'build', '--key', file)
    expect(result.code).toBe(EXIT_OK)

    const doc = JSON.parse(result.out) as { keys: Record<string, unknown>[] }
    expect(doc.keys).toHaveLength(1)
    // The published key carries no private member and no signing capability.
    expect(Object.keys(doc.keys[0] as object).sort()).toEqual(['crv', 'kid', 'kty', 'x'])
    expect(result.err).toContain('/.well-known/http-message-signatures-directory')
  })

  it('needs at least one key', async () => {
    expect((await invoke('directory', 'build')).code).toBe(EXIT_USAGE)
  })
})

describe('badge policy', () => {
  const write = async (name: string, contents: string): Promise<string> => {
    const file = join(dir, name)
    await writeFile(file, contents)
    return file
  }

  it('accepts a valid YAML policy', async () => {
    const file = await write(
      'ok.yaml',
      [
        'version: 1',
        'default: log-only',
        'rules:',
        '  - id: r',
        '    action: deny',
        '    when: { class: untrusted }',
      ].join('\n'),
    )
    const result = await invoke('policy', 'lint', file)
    expect(result.code).toBe(EXIT_OK)
    expect(result.out).toContain('policy is valid')
  })

  it('rejects an invalid policy with the path to the problem', async () => {
    const file = await write('bad.yaml', 'version: 1\ndefault: log_only\n')
    const result = await invoke('policy', 'lint', file)
    expect(result.code).toBe(EXIT_FAILED)
    expect(result.err).toContain('at default')
  })

  it('surfaces lint warnings but still exits zero', async () => {
    const file = await write('warn.yaml', 'version: 1\ndefault: deny\n')
    const result = await invoke('policy', 'lint', file)
    expect(result.out).toContain('default-denies-everything')
    expect(result.code).toBe(EXIT_OK)
  })

  it('fails on warnings under --strict, for CI', async () => {
    const file = await write('warn2.yaml', 'version: 1\ndefault: deny\n')
    expect((await invoke('policy', 'lint', file, '--strict')).code).toBe(EXIT_FAILED)
  })

  it('reports a missing file as a usage error', async () => {
    expect((await invoke('policy', 'lint', join(dir, 'nope.yaml'))).code).toBe(EXIT_USAGE)
  })

  it('prints an example that lints clean', async () => {
    const example = await invoke('policy', 'example')
    const file = await write('example.json', example.out)
    const result = await invoke('policy', 'lint', file, '--strict')
    expect(result.code).toBe(EXIT_OK)
  })
})

describe('badge report', () => {
  const LINES = [
    {
      ts: '2026-09-01T00:00:00Z',
      status: 'unknown',
      class: 'absent',
      reason: 'no_signature_fields',
      action: 'log-only',
      rule: 'default',
      would_action: 'log-only',
    },
    {
      ts: '2026-09-02T00:00:00Z',
      status: 'verified',
      class: 'ok',
      reason: 'ok',
      action: 'log-only',
      rule: 'docs-open',
      would_action: 'allow',
      operator: 'example',
      signature_agent: 'https://agent.example',
    },
    {
      ts: '2026-09-03T00:00:00Z',
      status: 'claimed',
      class: 'untrusted',
      reason: 'signature_invalid',
      action: 'log-only',
      rule: 'forgeries',
      would_action: 'deny',
      signature_agent: 'https://agent.example',
    },
    {
      ts: '2026-09-03T01:00:00Z',
      status: 'claimed',
      class: 'unverifiable',
      reason: 'directory_timeout',
      action: 'log-only',
      rule: 'default',
      would_action: 'log-only',
      signature_agent: 'https://slow.example',
    },
  ]

  const logFile = async (lines: unknown[], extra = ''): Promise<string> => {
    const file = join(dir, `log-${Math.random().toString(36).slice(2)}.jsonl`)
    await writeFile(file, `${lines.map((l) => JSON.stringify(l)).join('\n')}\n${extra}`)
    return file
  }

  it('summarises verdicts, actions and reasons', async () => {
    const result = await invoke('report', await logFile(LINES))
    expect(result.code).toBe(EXIT_OK)
    expect(result.out).toContain('4 decisions')
    expect(result.out).toContain('verified/ok')
    expect(result.out).toContain('signature_invalid')
  })

  // The one number an operator needs before enforcing.
  it('says how much currently-served traffic enforcing would refuse', async () => {
    const result = await invoke('report', await logFile(LINES))
    expect(result.out).toContain('1 request(s) that are served today would be refused')
    expect(result.out).toContain('by rule "forgeries"')
  })

  it('says so plainly when enforcing would change nothing', async () => {
    const harmless = LINES.filter((l) => l.would_action !== 'deny')
    const result = await invoke('report', await logFile(harmless))
    expect(result.out).toContain('Enforcing looks safe')
  })

  // Warning the operator about the trap the whole class axis exists to prevent.
  it('flags decisions that failed because Badge could not check', async () => {
    const result = await invoke('report', await logFile(LINES))
    expect(result.out).toContain('not because the caller did anything wrong')
  })

  it('groups an agent under one entry whether or not a record labelled it', async () => {
    const result = await invoke('report', await logFile(LINES))
    expect(result.out).toContain('https://agent.example (example)')
    expect(result.out.match(/https:\/\/agent\.example/g)).toHaveLength(1)
  })

  it('explains that a non-dry-run log cannot predict anything', async () => {
    const plain = LINES.map(({ would_action: _ignored, ...rest }) => rest)
    const result = await invoke('report', await logFile(plain))
    expect(result.out).toContain('was not recorded in dry run')
  })

  it('skips unparsable lines instead of giving up', async () => {
    const result = await invoke('report', await logFile(LINES, 'not json at all\n'))
    expect(result.code).toBe(EXIT_OK)
    expect(result.out).toContain('1 lines could not be parsed')
  })

  it('emits JSON on request', async () => {
    const result = await invoke('report', await logFile(LINES), '--json')
    const parsed = JSON.parse(result.out) as {
      total: number
      dryRun: { newlyDenied: number; byRule: Record<string, number> }
    }
    expect(parsed.total).toBe(4)
    expect(parsed.dryRun.newlyDenied).toBe(1)
    expect(parsed.dryRun.byRule).toEqual({ forgeries: 1 })
  })

  it('fails when the log has no usable records', async () => {
    const file = join(dir, 'empty.jsonl')
    await writeFile(file, '\n')
    expect((await invoke('report', file)).code).toBe(EXIT_FAILED)
  })

  it('reports an unreadable file as a usage error', async () => {
    expect((await invoke('report', join(dir, 'nope.jsonl'))).code).toBe(EXIT_USAGE)
  })

  it('rejects a nonsensical --top', async () => {
    expect((await invoke('report', await logFile(LINES), '--top', '0')).code).toBe(EXIT_USAGE)
  })
})

describe('badge verify', () => {
  const publicKeyFile = async (): Promise<string> => {
    const file = join(dir, `pub-${Math.random().toString(36).slice(2)}.json`)
    await writeFile(file, JSON.stringify(key.publicJwk))
    return file
  }

  it('verifies a captured request against a local key', async () => {
    const signed = await signRequest({ key, authority: 'example.com' })
    const result = await invoke(
      'verify',
      '--url',
      'https://example.com/',
      '--key',
      await publicKeyFile(),
      ...headerArgs(signed.headers),
    )
    expect(result.code).toBe(EXIT_OK)
    expect(result.out).toContain('status:   verified')
    expect(result.out).toContain('reason:   ok')
  })

  it('emits the verdict as JSON on request', async () => {
    const signed = await signRequest({ key, authority: 'example.com' })
    const result = await invoke(
      'verify',
      '--url',
      'https://example.com/',
      '--json',
      '--key',
      await publicKeyFile(),
      ...headerArgs(signed.headers),
    )
    expect(JSON.parse(result.out)).toMatchObject({ status: 'verified', reason: 'ok' })
  })

  // The line that turns a reason code into an action.
  it('says plainly whose problem a forged signature is', async () => {
    const signed = await signRequest({ key, authority: 'example.com', tamperSignature: true })
    const result = await invoke(
      'verify',
      '--url',
      'https://example.com/',
      '--key',
      await publicKeyFile(),
      ...headerArgs(signed.headers),
    )
    expect(result.code).toBe(EXIT_FAILED)
    expect(result.out).toContain('reason:   signature_invalid')
    expect(result.out).toContain('assume hostile')
  })

  it("says plainly when a failure is ours rather than the caller's", async () => {
    const signed = await signRequest({ key, authority: 'example.com' })
    const result = await invoke(
      'verify',
      '--url',
      'https://example.com/',
      '--offline',
      ...headerArgs(signed.headers),
    )
    expect(result.out).toContain('key_not_found')
  })

  it('reports an unsigned request as making no claim', async () => {
    const result = await invoke('verify', '--url', 'https://example.com/', '--offline')
    expect(result.out).toContain('no_signature_fields')
    expect(result.out).toContain('ordinary traffic')
  })

  it('rejects a malformed --header', async () => {
    const result = await invoke('verify', '--url', 'https://example.com/', '--header', 'nocolon')
    expect(result.code).toBe(EXIT_USAGE)
    expect(result.err).toContain('Name: value')
  })
})
