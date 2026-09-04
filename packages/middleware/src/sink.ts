import type { DecisionRecord } from './record.js'

/**
 * Where decision records go.
 *
 * Synchronous and returning nothing on purpose: a sink sits on the request
 * path, and one that can be awaited is one that can hold up a response.
 */
export interface Sink {
  record(record: DecisionRecord): void
}

/**
 * Wrap sinks so a broken one cannot take down the request it is describing.
 *
 * Logging is the least important thing happening on this code path, and it
 * should behave that way when it fails.
 */
export function compositeSink(...sinks: readonly Sink[]): Sink {
  return {
    record(entry) {
      for (const sink of sinks) {
        try {
          sink.record(entry)
        } catch {
          // Deliberately swallowed.
        }
      }
    },
  }
}

export interface JsonSinkOptions {
  readonly write?: (line: string) => void
  /**
   * Fraction of `unknown` verdicts to record, between 0 and 1.
   *
   * Unsigned traffic is most of the internet. Logging all of it drowns the
   * signal and costs more than the verification does, so it is sampled by
   * default. Every other verdict is always recorded.
   */
  readonly sampleUnknown?: number
  readonly random?: () => number
}

/** One JSON object per line — greppable, and what every log shipper expects. */
export function jsonSink(options: JsonSinkOptions = {}): Sink {
  const write = options.write ?? ((line: string) => process.stdout.write(`${line}\n`))
  const sampleUnknown = options.sampleUnknown ?? 0.01
  const random = options.random ?? Math.random
  return {
    record(entry) {
      if (entry.status === 'unknown' && random() >= sampleUnknown) return
      write(JSON.stringify(entry))
    },
  }
}

export interface MetricsSnapshot {
  /** Keyed `status|class|action|rule`. */
  readonly decisions: ReadonlyMap<string, number>
  /** Keyed by cache tier. */
  readonly directoryCache: ReadonlyMap<string, number>
  readonly directoryFetchCount: number
  readonly directoryFetchTotalUs: number
}

export interface MetricsSink extends Sink {
  snapshot(): MetricsSnapshot
}

export function metricsSink(): MetricsSink {
  const decisions = new Map<string, number>()
  const directoryCache = new Map<string, number>()
  let directoryFetchCount = 0
  let directoryFetchTotalUs = 0

  const bump = (map: Map<string, number>, key: string): void => {
    map.set(key, (map.get(key) ?? 0) + 1)
  }

  return {
    record(entry) {
      bump(decisions, `${entry.status}|${entry.class}|${entry.action}|${entry.rule}`)
      if (entry.cache !== undefined) bump(directoryCache, entry.cache)
      if (entry.directory_us !== undefined) {
        directoryFetchCount += 1
        directoryFetchTotalUs += entry.directory_us
      }
    },
    snapshot: () => ({
      decisions: new Map(decisions),
      directoryCache: new Map(directoryCache),
      directoryFetchCount,
      directoryFetchTotalUs,
    }),
  }
}

/** Render a snapshot as Prometheus text exposition, for an existing /metrics route. */
export function renderPrometheus(snapshot: MetricsSnapshot): string {
  const lines: string[] = [
    '# HELP badge_decisions_total Policy decisions by verdict and rule.',
    '# TYPE badge_decisions_total counter',
  ]
  for (const [key, count] of snapshot.decisions) {
    const [status, klass, action, rule] = key.split('|')
    lines.push(
      `badge_decisions_total{status="${escape(status)}",class="${escape(klass)}",` +
        `action="${escape(action)}",rule="${escape(rule)}"} ${count}`,
    )
  }
  lines.push(
    '# HELP badge_directory_cache_total Key directory lookups by cache tier.',
    '# TYPE badge_directory_cache_total counter',
  )
  for (const [tier, count] of snapshot.directoryCache) {
    lines.push(`badge_directory_cache_total{result="${escape(tier)}"} ${count}`)
  }
  lines.push(
    '# HELP badge_directory_fetch_seconds_sum Time spent resolving keys.',
    '# TYPE badge_directory_fetch_seconds_sum counter',
    `badge_directory_fetch_seconds_sum ${snapshot.directoryFetchTotalUs / 1_000_000}`,
    '# HELP badge_directory_fetch_seconds_count Key resolutions observed.',
    '# TYPE badge_directory_fetch_seconds_count counter',
    `badge_directory_fetch_seconds_count ${snapshot.directoryFetchCount}`,
  )
  return `${lines.join('\n')}\n`
}

function escape(value: string | undefined): string {
  return (value ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')
}
