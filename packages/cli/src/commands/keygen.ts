import type { webcrypto } from 'node:crypto'
import { writeFile } from 'node:fs/promises'
import { parseArgs } from 'node:util'
import { jwkThumbprint, type Jwk } from '@badge/core'
import { EXIT_OK, type Io } from '../io.js'

export async function keygen(argv: readonly string[], io: Io): Promise<number> {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      out: { type: 'string' },
      nbf: { type: 'string' },
      exp: { type: 'string' },
    },
  })

  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as webcrypto.CryptoKeyPair
  const privateJwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as Jwk
  const exported = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as Jwk

  const publicJwk: Jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: exported.x as string,
    ...(values.nbf === undefined ? {} : { nbf: Number(values.nbf) }),
    ...(values.exp === undefined ? {} : { exp: Number(values.exp) }),
  }
  const keyid = await jwkThumbprint(publicJwk)

  // Store only the members that matter. WebCrypto exports `alg: "Ed25519"`,
  // which is neither the JWA name (`EdDSA`) nor the HTTP Message Signatures
  // registry name (`ed25519`) the directory draft restricts `alg` to, and a
  // wrong `alg` published in a directory is worse than no `alg` at all. `ext`
  // and `key_ops` are WebCrypto bookkeeping with no business in a key file.
  const storedPrivate = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: publicJwk.x,
    d: (privateJwk as unknown as { d?: string }).d,
    kid: keyid,
    ...(values.nbf === undefined ? {} : { nbf: Number(values.nbf) }),
    ...(values.exp === undefined ? {} : { exp: Number(values.exp) }),
  }

  if (values.out !== undefined) {
    // 0600: a signing key on a shared machine should not be world-readable.
    await writeFile(values.out, `${JSON.stringify(storedPrivate, null, 2)}\n`, {
      mode: 0o600,
    })
    io.err(`private key written to ${values.out} (mode 0600) — do not publish this file`)
    io.out(JSON.stringify({ keyid, publicJwk }, null, 2))
    return EXIT_OK
  }

  io.err('no --out given, so the private key is printed below; redirect it somewhere safe')
  io.out(JSON.stringify({ keyid, publicJwk, privateJwk: storedPrivate }, null, 2))
  return EXIT_OK
}
