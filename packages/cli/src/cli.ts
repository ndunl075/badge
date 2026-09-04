import { EXIT_OK, EXIT_USAGE, UsageError, type Io } from './io.js'
import { directory } from './commands/directory.js'
import { keygen } from './commands/keygen.js'
import { policy } from './commands/policy.js'
import { report } from './commands/report.js'
import { verify } from './commands/verify.js'

const HELP = `badge — Web Bot Auth tools

  badge verify --url <url> --header "Signature-Input: ..." [--header ...]
      Verify a captured request and explain the verdict.
      --key <jwk>   verify against a local public key instead of fetching a directory
      --offline     never fetch a directory
      --json        emit the verdict as JSON

  badge keygen [--out <file>] [--nbf <unix>] [--exp <unix>]
      Generate an Ed25519 key pair and print its RFC 7638 thumbprint.

  badge directory build --key <file> [--key <file>] [--max-age <seconds>]
      Build the JWKS to serve at /.well-known/http-message-signatures-directory.

  badge directory fetch <https://origin>
      Fetch a live directory and report what a verifier would make of it.

  badge policy lint <file> [--strict]
      Validate and lint a policy, in YAML or JSON.

  badge policy example
      Print a worked example policy.

  badge report [<decision-log.jsonl>] [--json] [--top <n>]
      Summarise a decision log, and say what enforcing would change.
      Reads stdin when no file is given.

Exit codes: 0 success, 1 the thing being checked is wrong, 2 the command was used wrong.
`

export async function run(argv: readonly string[], io: Io): Promise<number> {
  const [command, ...rest] = argv
  try {
    switch (command) {
      case undefined:
      case '--help':
      case '-h':
      case 'help':
        io.out(HELP)
        return EXIT_OK
      case 'verify':
        return await verify(rest, io)
      case 'keygen':
        return await keygen(rest, io)
      case 'directory':
        return await directory(rest, io)
      case 'policy':
        return await policy(rest, io)
      case 'report':
        return await report(rest, io)
      default:
        io.err(`unknown command: ${command}`)
        io.err(HELP)
        return EXIT_USAGE
    }
  } catch (err) {
    if (err instanceof UsageError) {
      io.err(err.message)
      return EXIT_USAGE
    }
    io.err(err instanceof Error ? err.message : String(err))
    return EXIT_USAGE
  }
}
