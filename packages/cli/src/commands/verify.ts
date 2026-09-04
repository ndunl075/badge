import { readFile } from 'node:fs/promises'
import { parseArgs } from 'node:util'
import {
  createRequest,
  createVerifier,
  staticKeyResolver,
  toPublicJwk,
  type Jwk,
  type KeyResolver,
} from '@badge/core'
import { createDirectoryResolver } from '@badge/directory'
import { EXIT_FAILED, EXIT_OK, UsageError, type Io } from '../io.js'

/**
 * Verify a captured request and explain the verdict.
 *
 * The debugging tool the whole project is for: paste the URL and the three
 * headers from a request that was rejected, and get back the reason, the class,
 * and whose problem it is.
 */
export async function verify(argv: readonly string[], io: Io): Promise<number> {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      url: { type: 'string' },
      method: { type: 'string' },
      header: { type: 'string', multiple: true },
      key: { type: 'string', multiple: true },
      offline: { type: 'boolean' },
      json: { type: 'boolean' },
    },
  })

  if (values.url === undefined) {
    throw new UsageError(
      'usage: badge verify --url <url> --header "Signature-Input: ..." [--header ...] [--key <jwk>] [--offline]',
    )
  }

  const url = new URL(values.url)
  const headers: [string, string][] = []
  for (const raw of values.header ?? []) {
    const colon = raw.indexOf(':')
    if (colon === -1) throw new UsageError(`--header must look like "Name: value", got ${raw}`)
    headers.push([raw.slice(0, colon).trim(), raw.slice(colon + 1).trim()])
  }

  const request = createRequest({
    method: values.method ?? 'GET',
    scheme: url.protocol === 'https:' ? 'https' : 'http',
    authority: url.host,
    path: url.pathname,
    query: url.search.startsWith('?') ? url.search.slice(1) : url.search,
    headers,
  })

  const keys: KeyResolver = await resolver(values.key ?? [], values.offline === true)
  const verdict = await createVerifier({ keys }).verify(request)

  if (values.json === true) {
    io.out(JSON.stringify(verdict, null, 2))
  } else {
    io.out(`status:   ${verdict.status}`)
    io.out(`class:    ${verdict.class}`)
    io.out(`reason:   ${verdict.reason}`)
    io.out(`profile:  ${verdict.profile}`)
    if (verdict.signatureAgent !== undefined) io.out(`agent:    ${verdict.signatureAgent}`)
    if (verdict.keyid !== undefined) io.out(`keyid:    ${verdict.keyid}`)
    if (verdict.covered !== undefined) io.out(`covered:  ${verdict.covered.join(', ')}`)
    io.out('')
    io.out(explain(verdict.class))
  }
  return verdict.status === 'verified' ? EXIT_OK : EXIT_FAILED
}

async function resolver(keyFiles: readonly string[], offline: boolean): Promise<KeyResolver> {
  if (keyFiles.length > 0) {
    const keys: Jwk[] = []
    for (const file of keyFiles) {
      keys.push(toPublicJwk(JSON.parse(await readFile(file, 'utf8')) as Jwk))
    }
    return staticKeyResolver({ '*': keys })
  }
  if (offline) return staticKeyResolver({})
  return createDirectoryResolver()
}

/** The line that turns a reason code into an action. */
function explain(failureClass: string): string {
  switch (failureClass) {
    case 'ok':
      return 'Verified: the caller controls a key published at the origin it named. That is all it means.'
    case 'absent':
      return 'The caller made no Web Bot Auth claim at all. This is ordinary traffic.'
    case 'malformed':
      return "The caller's problem: it sent a claim it got wrong."
    case 'expired':
      return "The caller's problem: the signature is outside its validity window. Check clocks on both sides."
    case 'untrusted':
      return "The caller's problem, and assume hostile: a claim that failed a check the caller controls."
    case 'unverifiable':
      return "Our problem, not the caller's: Badge could not complete the check. Do not treat this as an attack."
    default:
      return ''
  }
}
