import { readFile } from 'node:fs/promises'
import { parseArgs } from 'node:util'
import { EXAMPLE_POLICY, PolicyError, lintPolicy, parsePolicy } from '@badge/policy'
import { parse as parseYaml } from 'yaml'
import { EXIT_FAILED, EXIT_OK, EXIT_USAGE, UsageError, type Io } from '../io.js'

export async function policy(argv: readonly string[], io: Io): Promise<number> {
  const [subcommand, ...rest] = argv
  switch (subcommand) {
    case 'lint':
      return await lint(rest, io)
    case 'example':
      io.out(JSON.stringify(EXAMPLE_POLICY, null, 2))
      return EXIT_OK
    default:
      throw new UsageError('usage: badge policy <lint|example>')
  }
}

async function lint(argv: readonly string[], io: Io): Promise<number> {
  const { values, positionals } = parseArgs({
    args: [...argv],
    allowPositionals: true,
    options: { strict: { type: 'boolean' } },
  })
  const file = positionals[0]
  if (file === undefined) throw new UsageError('usage: badge policy lint <file> [--strict]')

  let source: string
  try {
    source = await readFile(file, 'utf8')
  } catch {
    io.err(`cannot read ${file}`)
    return EXIT_USAGE
  }

  let document: unknown
  try {
    // YAML is a superset of JSON, so one parser handles both.
    document = parseYaml(source) as unknown
  } catch (err) {
    io.err(`${file}: not valid YAML or JSON: ${err instanceof Error ? err.message : String(err)}`)
    return EXIT_FAILED
  }

  let parsed
  try {
    parsed = parsePolicy(document)
  } catch (err) {
    if (err instanceof PolicyError) {
      io.err(`${file}: ${err.message}`)
      return EXIT_FAILED
    }
    throw err
  }

  const diagnostics = lintPolicy(parsed)
  for (const diagnostic of diagnostics) {
    const where =
      diagnostic.ruleId === undefined
        ? diagnostic.path
        : `${diagnostic.path} (${diagnostic.ruleId})`
    io.out(`${diagnostic.severity}: ${where}: ${diagnostic.message} [${diagnostic.code}]`)
  }

  const warnings = diagnostics.filter((d) => d.severity === 'warning').length
  if (warnings === 0) {
    io.out(
      `${file}: policy is valid, ${parsed.rules?.length ?? 0} rule(s), default ${parsed.default}`,
    )
    return EXIT_OK
  }
  io.out(`${file}: ${warnings} warning(s)`)
  return values.strict === true ? EXIT_FAILED : EXIT_OK
}
