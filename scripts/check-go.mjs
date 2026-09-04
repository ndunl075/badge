#!/usr/bin/env node
/**
 * Run the Go sidecar's checks as part of `pnpm run check`.
 *
 * This exists because of a specific mistake: the sidecar was added with its own
 * CI job, and `pnpm run check` covered only the TypeScript. A commit that ran
 * gofmt but not prettier passed the local gate and turned main red, because no
 * single command covered both halves of the repository. Now one does.
 *
 * Go is optional for contributors who are only touching the TypeScript, so this
 * skips loudly rather than failing when the toolchain is absent. CI runs the
 * sidecar in its own job with Go guaranteed present, so nothing is lost there.
 */
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const sidecar = fileURLToPath(new URL('../sidecar', import.meta.url))

const run = (command, args) =>
  spawnSync(command, args, { cwd: sidecar, stdio: 'pipe', encoding: 'utf8' })

if (run('go', ['version']).error !== undefined) {
  console.log('check-go: no Go toolchain found, skipping the sidecar checks.')
  console.log('check-go: CI runs them regardless, so a Go regression will still be caught.')
  process.exit(0)
}

const unformatted = run('gofmt', ['-l', '.'])
if (unformatted.status !== 0) {
  console.error(unformatted.stderr.trim())
  process.exit(1)
}
if (unformatted.stdout.trim() !== '') {
  console.error('check-go: these files need gofmt:')
  console.error(unformatted.stdout.trim())
  process.exit(1)
}

for (const args of [
  ['vet', './...'],
  ['test', './...'],
]) {
  const result = run('go', args)
  if (result.status !== 0) {
    console.error(`check-go: go ${args.join(' ')} failed`)
    console.error(result.stdout.trim())
    console.error(result.stderr.trim())
    process.exit(1)
  }
}

console.log('check-go: sidecar gofmt, vet and tests pass.')
