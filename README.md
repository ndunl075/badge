# Badge

**Badge tells you who is knocking, and why you let them in.**

Badge is middleware for web servers. It inspects an incoming HTTP request, decides whether the
caller is a **verified** agent, a **claimed** one, or **unknown**, applies a policy you wrote, and
reports exactly why it decided that.

It implements [Web Bot Auth][wba] — a profile of [RFC 9421][rfc9421] HTTP Message Signatures — the
same check Cloudflare and Akamai run at the edge. Badge runs it at your origin, where most of the
web actually lives.

> [!WARNING]
> Pre-v0. Nothing here is published to npm yet and the API will change.
> The specification Badge implements is a set of individual IETF drafts that are **not**
> working-group adopted and are still moving.

## What it does

```
Signature-Agent: "https://agent.example"        →  verified   allow    (rule: docs-open-to-agents)
Signature-Agent: "https://agent.example"        →  claimed    deny     (reason: signature_invalid)
(directory fetch timed out)                     →  claimed    log-only (reason: directory_timeout)
(no signature fields)                           →  unknown    log-only (rule: default)
```

Every decision names the rule that produced it and the reason behind it. That is the whole product.

## Design commitments

- **Installing Badge cannot break your site.** The default policy is `log-only`, and Badge never
  denies a request because of _its own_ failure to check — a directory outage is `unverifiable`,
  never `untrusted`.
- **`verified` means one thing:** the caller controls a key published at the origin it named. It is
  not a reputation score. Badge ships no bundled allowlist of "good" bots.
- **No bot detection.** No fingerprinting, no heuristics. Badge only reads cryptographic claims the
  caller volunteered.
- **Policy is data, never code.** It can be reviewed, diffed, and linted in CI.

## Architecture

The full design — trust model, threat model, request path, data model, and the reasoning behind
every default — is in **[ARCHITECTURE.md](./ARCHITECTURE.md)**. Read that before contributing.

## Development

```bash
pnpm install
pnpm run check    # format check + build + test
```

Requires Node 20+.

## License

Apache-2.0. Copyright 2026 Badge contributors.

[wba]: https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/
[rfc9421]: https://www.rfc-editor.org/rfc/rfc9421.html
