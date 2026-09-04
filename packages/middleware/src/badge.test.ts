import { createRequest, staticKeyResolver, type NormalizedRequest } from '@badge/core'
import { EXAMPLE_POLICY, type Policy } from '@badge/policy'
import { fixedClock, generateSigningKey, signRequest, type SigningKey } from '@badge/testkit'
import { beforeAll, describe, expect, it } from 'vitest'
import { createBadge } from './badge.js'
import type { DecisionRecord } from './record.js'
import { jsonSink, metricsSink, renderPrometheus, type Sink } from './sink.js'

const NOW = 1_735_689_600
const ORIGIN = 'https://agent.example'

let key: SigningKey

beforeAll(async () => {
  key = await generateSigningKey()
})

const collector = (): Sink & { records: DecisionRecord[] } => {
  const records: DecisionRecord[] = []
  return { records, record: (r) => records.push(r) }
}

const badgeWith = (policy: Policy, extra: Record<string, unknown> = {}, sinks: Sink[] = []) =>
  createBadge({
    policy,
    keys: staticKeyResolver({ [ORIGIN]: [key.publicJwk] }),
    clock: fixedClock(NOW),
    sinks,
    ...extra,
  })

const unsigned = (): NormalizedRequest =>
  createRequest({ method: 'GET', scheme: 'https', authority: 'example.com', path: '/docs/intro' })

const signed = async (path = '/docs/intro') =>
  (await signRequest({ key, created: NOW, expires: NOW + 60, path })).request

describe('createBadge', () => {
  it('denies nothing out of the box', async () => {
    const badge = createBadge({
      keys: staticKeyResolver({}),
      clock: fixedClock(NOW),
      sinks: [],
    })
    expect((await badge.inspect(unsigned())).action).toBe('log-only')
  })

  it('verifies, applies the policy, and names the rule', async () => {
    const decision = await badgeWith(EXAMPLE_POLICY).inspect(await signed())
    expect(decision).toMatchObject({
      action: 'allow',
      ruleId: 'docs-open-to-known-agents',
      operator: 'example',
    })
    expect(decision.verdict.reason).toBe('ok')
  })

  it('records one entry per decision', async () => {
    const sink = collector()
    await badgeWith(EXAMPLE_POLICY, {}, [sink]).inspect(await signed())
    expect(sink.records).toHaveLength(1)
    expect(sink.records[0]).toMatchObject({
      status: 'verified',
      class: 'ok',
      reason: 'ok',
      action: 'allow',
      rule: 'docs-open-to-known-agents',
      operator: 'example',
      route: 'GET /docs/intro',
      authority: 'example.com',
      profile: 'wba-2026-03',
      signature_agent: ORIGIN,
      keyid: key.keyid,
    })
  })

  // The privacy boundary is the shape of the record, not a redaction pass.
  it('has nowhere to put a signature, a header or a body', async () => {
    const sink = collector()
    await badgeWith(EXAMPLE_POLICY, {}, [sink]).inspect(await signed())
    const serialized = JSON.stringify(sink.records[0])
    expect(serialized).not.toContain('signature-input')
    expect(serialized).not.toMatch(/:[A-Za-z0-9+/]{40,}=*:/)
  })

  describe('dry run', () => {
    const strict: Policy = {
      version: 1,
      default: 'log-only',
      rules: [{ id: 'block-all-agents', action: 'deny', when: { status: 'verified' } }],
    }

    it('reports what the policy would have done without doing it', async () => {
      const sink = collector()
      const decision = await badgeWith(strict, { dryRun: true }, [sink]).inspect(await signed())
      expect(decision.action).toBe('log-only')
      expect(sink.records[0]?.would_action).toBe('deny')
      expect(sink.records[0]?.rule).toBe('block-all-agents')
    })

    it('actually denies once dry run is off', async () => {
      const decision = await badgeWith(strict).inspect(await signed())
      expect(decision.action).toBe('deny')
    })

    it('omits would_action when not dry running', async () => {
      const sink = collector()
      await badgeWith(strict, {}, [sink]).inspect(await signed())
      expect('would_action' in (sink.records[0] as object)).toBe(false)
    })
  })

  it('keeps working when a sink throws', async () => {
    const broken: Sink = {
      record: () => {
        throw new Error('log shipper is down')
      },
    }
    const decision = await badgeWith(EXAMPLE_POLICY, {}, [broken]).inspect(await signed())
    expect(decision.action).toBe('allow')
  })
})

describe('jsonSink', () => {
  const record = (status: string): DecisionRecord => ({
    ts: '2026-09-04T00:00:00.000Z',
    status,
    class: status === 'unknown' ? 'absent' : 'ok',
    reason: status === 'unknown' ? 'no_signature_fields' : 'ok',
    action: 'log-only',
    rule: 'default',
    profile: 'wba-2026-03',
    route: 'GET /',
    authority: 'example.com',
    total_us: 5,
  })

  it('writes one JSON object per line', () => {
    const lines: string[] = []
    jsonSink({ write: (l) => lines.push(l) }).record(record('verified'))
    expect(JSON.parse(lines[0] as string)).toMatchObject({ status: 'verified' })
  })

  // Unsigned traffic is most of the internet; logging all of it drowns the
  // signal and costs more than the verification does.
  it('samples unknown verdicts', () => {
    const lines: string[] = []
    const sink = jsonSink({ write: (l) => lines.push(l), sampleUnknown: 0.5, random: () => 0.9 })
    sink.record(record('unknown'))
    expect(lines).toHaveLength(0)
  })

  it('never samples away a verdict that is not unknown', () => {
    const lines: string[] = []
    const sink = jsonSink({ write: (l) => lines.push(l), sampleUnknown: 0, random: () => 0.99 })
    sink.record(record('claimed'))
    expect(lines).toHaveLength(1)
  })

  it('keeps unknown records when the sample says so', () => {
    const lines: string[] = []
    const sink = jsonSink({ write: (l) => lines.push(l), sampleUnknown: 0.5, random: () => 0.1 })
    sink.record(record('unknown'))
    expect(lines).toHaveLength(1)
  })
})

describe('metricsSink', () => {
  it('counts decisions, cache tiers and directory time', async () => {
    const metrics = metricsSink()
    await badgeWith(EXAMPLE_POLICY, {}, [metrics]).inspect(await signed())
    const snapshot = metrics.snapshot()
    expect(snapshot.decisions.get('verified|ok|allow|docs-open-to-known-agents')).toBe(1)
    expect(snapshot.directoryCache.get('hit')).toBe(1)
    expect(snapshot.directoryFetchCount).toBe(1)
  })

  it('renders Prometheus exposition', async () => {
    const metrics = metricsSink()
    await badgeWith(EXAMPLE_POLICY, {}, [metrics]).inspect(await signed())
    const text = renderPrometheus(metrics.snapshot())
    expect(text).toContain('# TYPE badge_decisions_total counter')
    expect(text).toContain('badge_decisions_total{status="verified"')
    expect(text).toContain('badge_directory_cache_total{result="hit"}')
    expect(text.endsWith('\n')).toBe(true)
  })

  it('escapes label values', () => {
    const metrics = metricsSink()
    metrics.record({
      ts: '2026-09-04T00:00:00.000Z',
      status: 'verified',
      class: 'ok',
      reason: 'ok',
      action: 'allow',
      rule: 'weird"rule',
      profile: 'p',
      route: 'GET /',
      authority: 'example.com',
      total_us: 1,
    })
    expect(renderPrometheus(metrics.snapshot())).toContain('rule="weird\\"rule"')
  })
})
