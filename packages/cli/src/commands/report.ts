import { createReadStream } from 'node:fs'
import { createInterface } from 'node:readline'
import { parseArgs } from 'node:util'
import { reasonInfo, type ReasonCode } from '@badge/core'
import { EXIT_FAILED, EXIT_OK, EXIT_USAGE, UsageError, type Io } from '../io.js'

/**
 * Turn a decision log into a decision.
 *
 * Dry run answers "what would this policy have done"; without something to read
 * the answer, an operator is left grepping JSON to work out whether it is safe
 * to enforce. This is that something, and its job is to make the one dangerous
 * number impossible to miss: how many requests that are currently served would
 * start being refused.
 */
interface LogRecord {
  status?: string
  class?: string
  reason?: string
  action?: string
  would_action?: string
  rule?: string
  operator?: string
  signature_agent?: string
  ts?: string
}

class Counter {
  private readonly counts = new Map<string, number>()

  add(key: string, by = 1): void {
    this.counts.set(key, (this.counts.get(key) ?? 0) + by)
  }

  get total(): number {
    let sum = 0
    for (const n of this.counts.values()) sum += n
    return sum
  }

  ranked(limit = Number.POSITIVE_INFINITY): [string, number][] {
    return [...this.counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit)
  }

  get(key: string): number {
    return this.counts.get(key) ?? 0
  }

  toObject(): Record<string, number> {
    return Object.fromEntries(this.ranked())
  }
}

export async function report(argv: readonly string[], io: Io): Promise<number> {
  const { values, positionals } = parseArgs({
    args: [...argv],
    allowPositionals: true,
    options: { json: { type: 'boolean' }, top: { type: 'string' } },
  })
  const file = positionals[0]
  const top = values.top === undefined ? 10 : Number(values.top)
  if (!Number.isFinite(top) || top < 1) throw new UsageError('--top must be a positive number')

  const verdicts = new Counter()
  const actions = new Counter()
  const wouldActions = new Counter()
  const reasons = new Counter()
  const agents = new Counter()
  // Keyed by origin, not by "operator (origin)": the same agent appears under
  // both forms otherwise, because a record only carries an operator label when
  // the policy in force at the time defined one.
  const operatorByAgent = new Map<string, string>()
  const rulesThatWouldDeny = new Counter()
  let total = 0
  let unparsable = 0
  let dryRunRecords = 0
  let firstTs: string | undefined
  let lastTs: string | undefined

  const input = file === undefined || file === '-' ? process.stdin : createReadStream(file)
  try {
    for await (const line of createInterface({ input, crlfDelay: Number.POSITIVE_INFINITY })) {
      if (line.trim() === '') continue
      let entry: LogRecord
      try {
        entry = JSON.parse(line) as LogRecord
      } catch {
        unparsable += 1
        continue
      }
      if (typeof entry.action !== 'string' || typeof entry.reason !== 'string') {
        unparsable += 1
        continue
      }

      total += 1
      verdicts.add(`${entry.status ?? '?'}/${entry.class ?? '?'}`)
      actions.add(entry.action)
      reasons.add(entry.reason)
      if (entry.signature_agent !== undefined) {
        agents.add(entry.signature_agent)
        if (entry.operator !== undefined) operatorByAgent.set(entry.signature_agent, entry.operator)
      }
      if (entry.would_action !== undefined) {
        dryRunRecords += 1
        wouldActions.add(entry.would_action)
        // The number that matters: served today, refused after the switch.
        if (entry.would_action === 'deny' && entry.action !== 'deny') {
          rulesThatWouldDeny.add(entry.rule ?? 'default')
        }
      }
      if (typeof entry.ts === 'string') {
        if (firstTs === undefined || entry.ts < firstTs) firstTs = entry.ts
        if (lastTs === undefined || entry.ts > lastTs) lastTs = entry.ts
      }
    }
  } catch (err) {
    io.err(`cannot read ${file ?? 'stdin'}: ${err instanceof Error ? err.message : String(err)}`)
    return EXIT_USAGE
  }

  if (total === 0) {
    io.err(
      unparsable === 0
        ? 'no decision records found'
        : `no usable records (${unparsable} unparsable lines)`,
    )
    return EXIT_FAILED
  }

  const unverifiable = reasonsInClass(reasons, 'unverifiable')
  const wouldDeny = rulesThatWouldDeny.total

  if (values.json === true) {
    io.out(
      JSON.stringify(
        {
          total,
          unparsable,
          window: { from: firstTs ?? null, to: lastTs ?? null },
          verdicts: verdicts.toObject(),
          actions: actions.toObject(),
          dryRun: {
            records: dryRunRecords,
            wouldActions: wouldActions.toObject(),
            newlyDenied: wouldDeny,
            byRule: rulesThatWouldDeny.toObject(),
          },
          reasons: reasons.toObject(),
          signatureAgents: agents.toObject(),
          operators: Object.fromEntries(operatorByAgent),
          unverifiable,
        },
        null,
        2,
      ),
    )
    return EXIT_OK
  }

  const pct = (n: number): string => `${((n / total) * 100).toFixed(1)}%`
  const rows = (entries: [string, number][]): void => {
    const width = Math.max(0, ...entries.map(([label]) => label.length))
    for (const [label, count] of entries) {
      io.out(`  ${label.padEnd(width)}  ${String(count).padStart(8)}  ${pct(count).padStart(6)}`)
    }
  }

  io.out(
    `${total} decisions${firstTs === undefined ? '' : ` from ${firstTs} to ${lastTs ?? firstTs}`}`,
  )
  if (unparsable > 0) io.out(`${unparsable} lines could not be parsed and were skipped`)

  io.out('\nverdicts')
  rows(verdicts.ranked(top))
  io.out('\nactions taken')
  rows(actions.ranked(top))
  io.out('\nreasons')
  rows(reasons.ranked(top))
  if (agents.total > 0) {
    io.out('\nsignature agents')
    rows(
      agents.ranked(top).map(([origin, count]) => {
        const label = operatorByAgent.get(origin)
        return [label === undefined ? origin : `${origin} (${label})`, count] as [string, number]
      }),
    )
  }

  if (dryRunRecords === 0) {
    io.out('\nThis log was not recorded in dry run, so there is nothing to predict.')
    io.out('Run Badge with dryRun: true to find out what enforcing would change.')
  } else {
    io.out(`\nif you turn dry run off (${dryRunRecords} records were dry run)`)
    rows(wouldActions.ranked(top))
    if (wouldDeny === 0) {
      io.out('\n  Nothing that is served today would be refused. Enforcing looks safe.')
    } else {
      io.out(
        `\n  ${wouldDeny} request(s) that are served today would be refused (${pct(wouldDeny)}):`,
      )
      for (const [rule, count] of rulesThatWouldDeny.ranked(top)) {
        io.out(`    ${count} by rule "${rule}"`)
      }
      io.out('\n  Check those are traffic you meant to turn away before enforcing.')
    }
  }

  if (unverifiable > 0) {
    io.out(
      `\n${unverifiable} decision(s) (${pct(unverifiable)}) failed because Badge could not complete` +
        '\nthe check, not because the caller did anything wrong. A rule that denies those ties' +
        "\nyour availability to the verifier's own uptime. Run `badge policy lint` to check.",
    )
  }

  return EXIT_OK
}

function reasonsInClass(reasons: Counter, wanted: string): number {
  let sum = 0
  for (const [reason, count] of reasons.ranked()) {
    try {
      if (reasonInfo(reason as ReasonCode).class === wanted) sum += count
    } catch {
      // An unrecognized reason code, most likely from a newer Badge. Skipped
      // rather than guessed at.
    }
  }
  return sum
}
