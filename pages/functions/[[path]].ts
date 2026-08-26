import { gate } from './_lib/gate'
import { originFor, forget, type Surface } from './_lib/origin'
import { signForOrigin } from './_lib/sign'

/**
 * The thin reverse proxy from §11's diagram.
 *
 * Access is bound to this Pages project, which means it protects the preview hostnames and
 * NOT the canonical <project>.pages.dev. That is the gap R16 has to enumerate and R24 has to
 * close, and nothing in this file closes it: a request arriving on the canonical hostname is
 * forwarded exactly as it came, without a token, and the origin refuses it. Inventing a
 * token here, or trusting the hostname the request arrived on, would be precisely the failure
 * §4 is written to catch.
 *
 * What this file does do: abuse control the free path has nowhere else to put (R29, R30), and
 * a signature over the hop to a quick tunnel that is public by design (see _lib/sign.ts).
 */

interface Env {
  MERIDIAN_KV: KVNamespace
  /** Shared with the origin. `wrangler pages secret put EDGE_HMAC_SECRET`. */
  EDGE_HMAC_SECRET: string
}

/** Headers that must not be copied onto the outbound request. */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length',
])

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env } = context
  const url = new URL(request.url)

  const ip = request.headers.get('cf-connecting-ip') ?? '0.0.0.0'
  const userAgent = request.headers.get('user-agent') ?? ''

  // R29/R30 — shared with the local stand-in so the two cannot drift. See _lib/gate.ts.
  const decision = await gate(env.MERIDIAN_KV, {
    method: request.method,
    pathname: url.pathname,
    search: url.search,
    ip,
    userAgent,
  })

  if (!decision.allow) {
    console.log(`[edge] ${decision.log}`)
    return json(decision.status, { error: decision.reason }, decision.headers)
  }

  const { surface, originPath } = decision

  const body = request.method === 'GET' || request.method === 'HEAD'
    ? new ArrayBuffer(0)
    : await request.arrayBuffer()

  const first = await forward(env, surface, originPath, request, body)
  if (first !== null) return first

  // The quick tunnel URL rotates on restart. One retry against a re-read KV value turns that
  // into a blip rather than an outage needing a redeploy.
  forget(surface)
  const second = await forward(env, surface, originPath, request, body)
  if (second !== null) return second

  console.log(`[edge] origin for ${surface} unreachable`)
  return json(502, { error: 'bad_gateway', surface })
}

async function forward(
  env: Env,
  surface: Surface,
  originPath: string,
  request: Request,
  body: ArrayBuffer,
): Promise<Response | null> {
  const origin = await originFor(env.MERIDIAN_KV, surface)
  if (origin === null) return null

  const target = `${origin.replace(/\/$/, '')}${originPath}`
  const signature = await signForOrigin(env.EDGE_HMAC_SECRET, request.method, originPath, body)

  const headers = new Headers()
  for (const [name, value] of request.headers) {
    if (!HOP_BY_HOP.has(name.toLowerCase())) headers.set(name, value)
  }

  // The whole reason this proxy exists: carry the token Access issued through to the code
  // that verifies it. Absent on the canonical hostname, and that absence is forwarded too.
  headers.set('X-Meridian-Timestamp', signature.timestamp)
  headers.set('X-Meridian-Nonce', signature.nonce)
  headers.set('X-Meridian-Signature', signature.signature)

  try {
    return await fetch(target, {
      method: request.method,
      headers,
      body: body.byteLength === 0 ? undefined : body,
      redirect: 'manual',
    })
  } catch {
    return null
  }
}

function json(status: number, payload: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json', ...extra },
  })
}
