# badge-proxy

A reverse proxy that runs the Badge doorman in front of any origin, whatever it is written in.

The TypeScript packages embed into a Node application. This does the same job for a Python, Ruby,
PHP, Java or Go origin: it sits in front, verifies Web Bot Auth signatures, applies the same policy
format, and forwards or refuses.

It is a **re-implementation, not a binding**. The two share no code, so they can disagree — which is
why both are checked against the same fixtures in `../spec-vectors/`. Those bases are hand-written
rather than generated from either implementation, so agreement between the three is worth something.

```bash
go test ./...
go run ./cmd/badge-proxy -config badge.yaml
```
