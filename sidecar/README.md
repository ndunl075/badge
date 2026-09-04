# badge-proxy

A reverse proxy that runs the Badge doorman in front of any origin, whatever it is written in.

The TypeScript packages embed into a Node application. This does the same job for a Python, Ruby,
PHP, Java or Go origin: it sits in front, verifies Web Bot Auth signatures, applies the same policy
format, and forwards or refuses.

It is a **re-implementation, not a binding**. The two share no code, so they can disagree — which is
why both are checked against the same fixtures in `../spec-vectors/`. Those bases are hand-written
rather than generated from either implementation, so agreement between the three is worth something.

```bash
go test -race ./...
go run ./cmd/badge-proxy -config badge.example.yaml
```

From the repository root, `pnpm run check` runs these alongside the TypeScript checks, so one
command gates the whole repository.

Start with `dryRun: true`. The proxy then evaluates the whole policy, records
what it _would_ have done in each decision record's `would_action`, and refuses
nothing. Feed that log to `badge report` from the TypeScript CLI — the record
format is the same — and it will tell you how much currently-served traffic
enforcing would turn away.

The default policy denies nothing, so putting this in front of a live site
cannot break it.

## What it shares with the TypeScript, and what it does not

It shares the **policy file format**, the **decision record format**, the
**reason codes**, and the fixtures in `../spec-vectors/`. It shares no code.

That is deliberate. Two implementations written from the same specification can
disagree, and the vectors are where that disagreement shows up as a test failure
rather than as a production incident. The reason code tables in particular are
duplicated, which is a real cost: `spec-vectors/verdicts.json` is what catches
the drift.

## Soak

`go test ./...` includes two flood tests that assert the bounded structures stay
bounded: every cache key, breaker key and in-flight slot is derived from the
attacker-supplied `Signature-Agent`, so "it has an LRU" and "the LRU is actually
reached on this path" are different claims. The breaker map was missed the first
time round precisely because nobody checked.

For a longer run against a live proxy:

```bash
go run ./cmd/soak -duration 60s -workers 32
```

It drives a realistic mix — mostly unsigned, some verified, some forged, and a
stream of origins an attacker just invented — and reports throughput, latency
percentiles, heap and goroutine counts, and the resolver's bounded state. A
20-second run on a 4-core container:

```
start   heap   0.2 MiB   goroutines    3
end     heap   2.3 MiB   goroutines   15

145463 requests in 20s across 24 workers (7273 req/s)
  HTTP 403: 14537
  HTTP 200: 130926
  latency p50 3.182ms  p95 6.709ms  p99 9.11ms

resolver state after a flood of invented origins:
  cached origins 1024 (bound 1024)
  breakers       2247 (bound 4096)
```

The throughput figure is not a production number — the load generator and the
proxy share four cores, and the upstream is in the same process. The numbers
that matter are the flat heap and the cache sitting exactly on its bound rather
than above it.
