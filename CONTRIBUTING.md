# Contributing to Badge

Read [ARCHITECTURE.md](./ARCHITECTURE.md) first. It is the contract the code is written against,
and where the code and that document disagree, one of them is a bug — say which in your PR.

## Before you open a PR

```bash
pnpm install
pnpm run check   # prettier, TypeScript build and tests, plus gofmt, go vet and go test
```

One command covers both halves of the repository on purpose. When the Go sidecar was added it had
its own CI job and `pnpm run check` covered only the TypeScript, so a commit that ran `gofmt` but
not prettier passed the local gate and turned `main` red. If you add a language, add it to `check`.

The Go toolchain is optional: `check` skips the sidecar loudly when Go is absent, and CI runs it
regardless.

## Things that are not up for debate lightly

These are load-bearing. Changing one is a design discussion, not a patch.

- **Reason codes are public API.** Codes may be added; they are never repurposed. A log line written
  a year ago must still mean what it meant then. The table lives in
  `packages/core/src/reasons.ts` and is asserted by tests.
- **A verdict always has a reason.** `verdictFor()` is the only constructor, and it derives status
  and class from the reason code, so the invariant holds by construction rather than by review.
- **`unverifiable` is never `untrusted`.** Anything meaning "Badge could not complete the check"
  must not be classed as hostile. Denying on it wires a site's availability to the verifier's own
  uptime.
- **Defaults cannot break a live site.** The shipped policy denies nothing. Any change that makes a
  fresh install more likely to reject traffic needs an explicit argument.
- **Adapters stay thin.** No verification logic in an adapter. The conformance suite in
  `packages/adapters/src/conformance.test.ts` asserts every adapter reaches an identical decision
  for an identical request; if you have to special-case one, something is in the wrong place.
- **Hand-written spec vectors stay hand-written.** `spec-vectors/signature-base.json` is an
  independent statement of what the RFC 9421 bytes must be. Do not regenerate it from the
  implementation — if it disagrees with the code, work out which one is wrong.

## Testing expectations

- Every reason code the verifier can emit has a test that produces it. A reason code with no test is
  a lie in the documentation.
- Failure paths get the same care as the happy path. Most of the value in a verifier is in what it
  refuses and how clearly it says so.
- Signed fixtures are regenerated with `pnpm run vectors:generate`. Ed25519 is deterministic and the
  key is fixed, so a diff in `spec-vectors/verdicts.json` means behaviour changed. Explain it.

## Specification changes

The Web Bot Auth drafts move. A new revision is a **new profile** in
`packages/core/src/profile.ts`, not an edit to the existing one — verdicts record which profile
judged them, and a log line from six months ago must still say which rules applied.
