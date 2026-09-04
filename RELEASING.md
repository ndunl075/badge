# Releasing

Badge publishes seven packages from one repository, all at the same version.
`@badge/interop` is deliberately not published: it is a test rig, and shipping it would put a
dependency on another implementation into everyone's lockfile.

## Before the first release

Two things are needed once, and neither can be done from inside this repository:

1. **Claim the `@badge` scope on npm** and confirm it is yours. As of writing, `@badge/core` returns
   a 404, which means unpublished — it does not prove the scope is unowned. Check before tagging;
   renaming after a release is far worse than renaming before one.
2. **Give the workflow a way to publish.** Either add an `NPM_TOKEN` secret with publish rights, or
   configure npm trusted publishing for this repository, which is better: it removes the long-lived
   token entirely. The workflow requests `id-token: write` so published tarballs carry provenance
   either way, tying each one to the workflow run and commit that built it.

## Cutting a release

```bash
pnpm run check                     # format, build, every test
pnpm -r exec npm version 0.2.0     # all packages move together
git commit -am "Release 0.2.0"
git tag v0.2.0
git push origin main --tags
```

The tag runs `.github/workflows/release.yml`, which re-runs the full check before publishing
anything. Nothing is published from a laptop.

## Versioning

Badge is pre-1.0 and the API will change. Until 1.0:

- The **reason codes** are the most stable surface and are treated as public API already: codes are
  added, never repurposed. See CONTRIBUTING.md.
- A new Web Bot Auth draft revision is a **new profile**, not a breaking release. Verdicts record
  which profile judged them, so a log line keeps its meaning across upgrades.
- Everything else may move in a minor version. Pin exactly if that matters to you.
