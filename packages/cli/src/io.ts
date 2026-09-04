/** Output, injected so commands can be tested without spawning a process. */
export interface Io {
  out(text: string): void
  err(text: string): void
}

export const consoleIo: Io = {
  out: (text) => process.stdout.write(`${text}\n`),
  err: (text) => process.stderr.write(`${text}\n`),
}

/** Exit codes: 0 success, 1 the thing being checked is wrong, 2 the command was used wrong. */
export const EXIT_OK = 0
export const EXIT_FAILED = 1
export const EXIT_USAGE = 2

export class UsageError extends Error {
  override readonly name = 'UsageError'
}
