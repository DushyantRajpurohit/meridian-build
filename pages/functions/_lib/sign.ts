/**
 * The Pages Function signs every request it forwards, and the origin refuses anything
 * unsigned.
 *
 * This is necessary on the free path and only on the free path. The origin sits on a public
 * `trycloudflare.com` URL, so "the request reached 127.0.0.1, therefore it came through the
 * edge" is not merely weak reasoning here — it is false. Without a signature, anyone who
 * learns the quick-tunnel URL walks straight past the rate limiter, past the filtering rule,
 * and past the Access application, and talks to Node directly.
 *
 * What this is NOT is identity. Holding the shared secret proves a request traversed this
 * Function; it says nothing whatsoever about who sent it. The origin therefore checks this
 * FIRST and then still demands a verified Access token on the gated surfaces. If this check
 * ever became a substitute for the token check, the build would have failed at its central
 * point — that is the R24 trap wearing a different hat.
 *
 * The nonce is inside the signed material so every forwarded request is unique and the origin
 * can keep a replay cache without rejecting two identical GETs that merely share a second.
 */

const encoder = new TextEncoder()

/**
 * The two helpers below pin `Uint8Array<ArrayBuffer>` rather than plain `Uint8Array`. This
 * file is compiled twice — once against @cloudflare/workers-types for the deployment, once
 * against @types/node because test/edge.test.ts imports it to check that both runtimes
 * produce the same bytes — and Node's `BufferSource` will not accept the `ArrayBufferLike`
 * that a bare `Uint8Array` annotation widens to.
 */

export interface EdgeSignature {
  timestamp: string
  nonce: string
  signature: string
}

export async function signForOrigin(
  secret: string,
  method: string,
  pathWithQuery: string,
  body: ArrayBuffer,
): Promise<EdgeSignature> {
  const timestamp = Math.floor(Date.now() / 1000).toString()
  const nonce = crypto.randomUUID()
  const material = canonical(method, pathWithQuery, nonce, body)

  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const digest = await crypto.subtle.sign('HMAC', key, prefixed(timestamp, material))

  return { timestamp, nonce, signature: hex(digest) }
}

/**
 * `${method}\n${path}\n${nonce}\n` followed by the raw body bytes.
 *
 * Method and path are in there so a signature captured from a GET cannot be lifted onto a
 * POST to another route. The origin rebuilds this byte-for-byte; see src/access/edge.ts.
 */
function canonical(method: string, pathWithQuery: string, nonce: string, body: ArrayBuffer): Uint8Array<ArrayBuffer> {
  const head = encoder.encode(`${method}\n${pathWithQuery}\n${nonce}\n`)
  const out = new Uint8Array(head.length + body.byteLength)
  out.set(head, 0)
  out.set(new Uint8Array(body), head.length)
  return out
}

function prefixed(timestamp: string, material: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const head = encoder.encode(`${timestamp}.`)
  const out = new Uint8Array(head.length + material.length)
  out.set(head, 0)
  out.set(material, head.length)
  return out
}

function hex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('')
}
