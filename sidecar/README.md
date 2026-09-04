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

Start with `dryRun: true`. The proxy then evaluates the whole policy, records
what it *would* have done in each decision record's `would_action`, and refuses
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
