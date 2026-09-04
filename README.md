# Badge

**Badge tells you who is knocking, and why you let them in.**

Badge is middleware for web servers. It inspects an incoming HTTP request, decides whether the
caller is a **verified** agent, a **claimed** one, or **unknown**, applies a policy you wrote, and
reports exactly why it decided that.

It implements [Web Bot Auth][wba] — a profile of [RFC 9421][rfc9421] HTTP Message Signatures — the
same check Cloudflare and Akamai run at the edge. Badge runs it at your origin, where most of the
web actually lives.

> [!WARNING]
> Pre-v0. Nothing is published to npm yet and the API will change. The specification Badge
> implements is a set of individual IETF drafts that are **not** working-group adopted and are
> still moving — the directory draft has already been renamed once.

## See it work

```bash
pnpm install && pnpm run build
node examples/demo.mjs
```

That starts a real server with a real policy and sends it four real requests:

```
an ordinary browser, no signature
   ->   200  unknown/no_signature_fields  rule=default

a verified agent reading the docs
   ->   200  verified/ok                  rule=docs-open-to-agents

a forged signature
   ->   403  claimed/signature_invalid    rule=forgeries-are-hostile

an expired signature
   ->   200  claimed/signature_expired    rule=default

a verified agent at checkout
   ->   403  verified/ok                  rule=no-agents-at-checkout
```

Every decision names the rule that produced it and the reason behind it. That is the whole product.

## Install it

```ts
import { badgeNodeMiddleware } from '@badge/adapters'
import { createBadge } from '@badge/middleware'

const badge = createBadge({ policy }) // defaults to log-only: it cannot break your site
app.use(badgeNodeMiddleware(badge))
```

Adapters ship for `node:http`, Connect and Express, Fastify, and any fetch-style runtime
(Hono, Workers, Deno, Bun). They are deliberately thin — build a request, call `inspect`, apply the
result — and a shared conformance suite asserts every one of them reaches an identical decision for
an identical request.

## Write a policy

```yaml
version: 1
default: log-only # nothing is denied until you say so

operators:
  example: ['https://agent.example'] # labels you author; Badge ships no allowlist

rules:
  - id: forgeries-are-hostile
    when: { class: untrusted }
    action: deny

  - id: our-outage-is-not-their-fault
    when: { class: unverifiable }
    action: log-only

  - id: docs-open-to-known-agents
    when: { status: verified, operator: example }
    routes: ['GET /docs/**']
    action: allow
```

```bash
badge policy lint policy.yaml --strict   # gate it in CI
```

Those first two rules are the ones people get wrong, and the linter is built around them. A rule
saying `when: { status: claimed }` with `action: deny` also denies `directory_timeout` — a request
that failed because _Badge_ could not reach the key directory, not because the caller did anything
wrong. `badge policy lint` computes that exactly, by enumerating the closed reason set against your
condition, and tells you.

## Debug a rejection

```
$ badge verify --url https://example.com/docs --header 'Signature-Input: ...' --header 'Signature: ...'
status:   claimed
class:    untrusted
reason:   signature_invalid

The caller's problem, and assume hostile: a claim that failed a check the caller controls.
```

```
$ badge directory fetch https://agent.example
```

shows the thumbprints an origin actually publishes, which is what the `keyid` in that log line has
to match.

## Design commitments

- **Installing Badge cannot break your site.** The default policy is `log-only`, and Badge never
  denies a request because of _its own_ failure to check. Verdicts carry a failure class alongside
  the headline status precisely so `signature_invalid` (hostile) and `directory_timeout` (our
  problem) can never share a policy outcome.
- **`verified` means one thing:** the caller controls a key published at the origin it named. It is
  not a reputation score. Badge ships no bundled allowlist of "good" bots, because no trust registry
  exists yet and anyone can stand up a directory.
- **No bot detection.** No fingerprinting, no heuristics, no scoring. Badge only reads
  cryptographic claims the caller volunteered.
- **Policy is data, never code.** No expression language, nothing evaluated. It can be reviewed,
  diffed and linted like any other configuration.
- **`Signature-Agent` is treated as attacker-controlled input**, because it is. The directory client
  refuses non-public addresses, follows no redirects, pins DNS so it cannot be rebound between the
  check and the connection, caps body size and time, dedupes and caches, and trips a per-origin
  breaker rather than hammering a broken directory.

## Packages

| Package             | What it is                                                                         |
| ------------------- | ---------------------------------------------------------------------------------- |
| `@badge/core`       | Verdicts, reason codes, RFC 9651 parsing, RFC 9421 base construction, the verifier |
| `@badge/policy`     | Policy schema, matcher, linter                                                     |
| `@badge/directory`  | Key directory client (guards, caches, breaker) and server helper                   |
| `@badge/middleware` | Composes verifier + policy + sinks; decision records and metrics                   |
| `@badge/adapters`   | node/Connect/Express, Fastify, fetch/Hono                                          |
| `@badge/testkit`    | Request signer, fixtures, movable clock                                            |
| `@badge/cli`        | `badge verify`, `keygen`, `directory`, `policy`                                    |

`spec-vectors/` holds cross-implementation fixtures. The signature-base vectors are written by hand
rather than generated, so any port of Badge has an independent statement of what the bytes must be.

## Architecture

The full design — trust model, threat model, request path, data model, and the reasoning behind
every default — is in **[ARCHITECTURE.md](./ARCHITECTURE.md)**. Read it before contributing; it is
the contract the code is written against, and where the two disagree, one of them is a bug.

## Development

```bash
pnpm install
pnpm run check              # format check + build + test
pnpm run vectors:generate   # regenerate the signed spec vectors
```

Requires Node 20+.

## License

Apache-2.0. Copyright 2026 Badge contributors.

[wba]: https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/
[rfc9421]: https://www.rfc-editor.org/rfc/rfc9421.html
