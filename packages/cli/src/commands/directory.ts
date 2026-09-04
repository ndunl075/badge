import { readFile } from 'node:fs/promises'
import { parseArgs } from 'node:util'
import { jwkThumbprint, keyValidityAt, toPublicJwk, type Jwk } from '@badge/core'
import { buildDirectory, nodeHttpClient, rotationWarnings } from '@badge/directory'
import { EXIT_FAILED, EXIT_OK, UsageError, type Io } from '../io.js'

export async function directory(argv: readonly string[], io: Io): Promise<number> {
  const [subcommand, ...rest] = argv
  switch (subcommand) {
    case 'build':
      return await build(rest, io)
    case 'fetch':
      return await fetchDirectory(rest, io)
    default:
      throw new UsageError('usage: badge directory <build|fetch>')
  }
}

async function build(argv: readonly string[], io: Io): Promise<number> {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      key: { type: 'string', multiple: true },
      'max-age': { type: 'string' },
    },
  })
  const files = values.key ?? []
  if (files.length === 0) {
    throw new UsageError('usage: badge directory build --key <file> [--key <file>]')
  }

  const keys: Jwk[] = []
  for (const file of files) {
    // Reduce to public members rather than refusing a private key outright:
    // `keygen --out` writes one, and requiring a second file to publish from is
    // friction that ends with someone publishing the wrong one.
    keys.push(toPublicJwk(JSON.parse(await readFile(file, 'utf8')) as Jwk))
  }

  const doc = await buildDirectory({
    keys,
    ...(values['max-age'] === undefined ? {} : { cacheMaxAgeSec: Number(values['max-age']) }),
  })
  const warnings = rotationWarnings(keys, Math.floor(Date.now() / 1000))
  for (const warning of warnings) io.err(`warning: ${warning}`)

  io.err(`serve this at ${doc.path} with content-type: ${doc.headers['content-type'] ?? ''}`)
  io.out(doc.body)
  return warnings.length === 0 ? EXIT_OK : EXIT_FAILED
}

/**
 * Fetch a live directory and report what a verifier would make of it.
 *
 * The command to reach for when an agent says it is signing and a site says it
 * is not: it shows the thumbprints the origin actually publishes, which is what
 * a `keyid` in a log line has to match.
 */
async function fetchDirectory(argv: readonly string[], io: Io): Promise<number> {
  const { positionals } = parseArgs({ args: [...argv], allowPositionals: true, options: {} })
  const origin = positionals[0]
  if (origin === undefined) throw new UsageError('usage: badge directory fetch <https://origin>')

  const url = `${new URL(origin).origin}/.well-known/http-message-signatures-directory`
  const response = await nodeHttpClient().get(url, { timeoutMs: 5000, maxBytes: 256 * 1024 })
  io.err(`GET ${url} -> ${response.status}`)

  if (response.status !== 200) {
    io.err(`directory returned HTTP ${response.status}`)
    return EXIT_FAILED
  }
  const contentType = response.headers.get('content-type') ?? '(none)'
  if (!contentType.startsWith('application/http-message-signatures-directory+json')) {
    io.err(
      `warning: content-type is ${contentType}, not ` +
        'application/http-message-signatures-directory+json',
    )
  }

  const parsed = JSON.parse(new TextDecoder().decode(response.body)) as { keys?: Jwk[] }
  const keys = parsed.keys
  if (!Array.isArray(keys)) {
    io.err('directory has no "keys" array')
    return EXIT_FAILED
  }

  const now = Math.floor(Date.now() / 1000)
  const described = await Promise.all(
    keys.map(async (jwk) => ({
      keyid: await jwkThumbprint(jwk).catch(() => '(unthumbprintable)'),
      kty: jwk.kty,
      crv: jwk.crv,
      validity: keyValidityAt(jwk, now),
      usableForWebBotAuth: jwk.kty === 'OKP' && jwk.crv === 'Ed25519',
    })),
  )
  io.out(JSON.stringify({ url, contentType, keys: described }, null, 2))
  for (const warning of rotationWarnings(keys, now)) io.err(`warning: ${warning}`)
  return described.some((k) => k.usableForWebBotAuth && k.validity === 'valid')
    ? EXIT_OK
    : EXIT_FAILED
}
