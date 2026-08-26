import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { gate } from '../pages/functions/_lib/gate'
import type { Surface } from '../pages/functions/_lib/origin'
import { signForOrigin } from '../pages/functions/_lib/sign'
import type { KeyValueStore } from '../pages/functions/_lib/store'

/**
 * A local stand-in for the Pages Function, so the two UIs can be opened in a browser.
 *
 * It runs the deployed code where it matters — `gate()` for R29/R30 and `signForOrigin()`
 * for the hop — and reimplements only the plumbing that Workers gives the real one for free.
 *
 * DEVELOPMENT ONLY, and one thing here would be a serious bug in production: when
 * `mintToken` is set, this injects an Access assertion the way Access does on a protected
 * hostname. That is a simulation of the identity provider, not of the origin, and the origin
 * still verifies every token it receives exactly as it would in production — signature,
 * issuer, expiry and audience. Nothing in this file is on the trust path, and nothing in
 * `src/` knows it exists.
 */

export interface LocalEdgeOptions {
  port: number
  label: string
  secret: string
  origins: Record<Surface, string>
  /** Set on the hostname Access protects; absent on the canonical one. */
  mintToken?: () => Promise<string>
}

/** In-memory stand-in for the KV namespace, satisfying the same structural type. */
export function memoryStore(): KeyValueStore {
  const map = new Map<string, string>()
  return {
    get: async (key) => map.get(key) ?? null,
    put: async (key, value) => {
      map.set(key, value)
    },
  }
}

const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'host', 'content-length'])

export async function startLocalEdge(options: LocalEdgeOptions): Promise<Server> {
  const store = memoryStore()

  const server = createServer((req, res) => {
    void handle(req, res).catch((error: unknown) => {
      res.writeHead(502, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'bad_gateway', detail: String(error) }))
    })
  })

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://127.0.0.1:${options.port}`)
    // One ArrayBuffer, used for both the signature and the forwarded body, so there is no
    // chance of signing one set of bytes and sending another.
    const body = await readBody(req)

    const decision = await gate(store, {
      method: req.method ?? 'GET',
      pathname: url.pathname,
      search: url.search,
      ip: '203.0.113.9', // a stable stand-in for cf-connecting-ip
      userAgent: header(req, 'user-agent') ?? '',
    })

    if (!decision.allow) {
      console.log(`[${options.label}] ${decision.log}`)
      res.writeHead(decision.status, { 'content-type': 'application/json', ...decision.headers })
      res.end(JSON.stringify({ error: decision.reason }))
      return
    }

    const { surface, originPath } = decision
    const signature = await signForOrigin(options.secret, req.method ?? 'GET', originPath, body)

    const headers = new Headers()
    for (const [name, value] of Object.entries(req.headers)) {
      if (value === undefined || HOP_BY_HOP.has(name)) continue
      headers.set(name, Array.isArray(value) ? value.join(', ') : value)
    }
    headers.set('X-Meridian-Timestamp', signature.timestamp)
    headers.set('X-Meridian-Nonce', signature.nonce)
    headers.set('X-Meridian-Signature', signature.signature)

    // The one line that differs between the two hostnames. On the canonical one there is no
    // mintToken, nothing is injected, and the origin refuses the request — which is R24.
    if (options.mintToken !== undefined) {
      headers.set('Cf-Access-Jwt-Assertion', await options.mintToken())
    }

    const upstream = await fetch(`${options.origins[surface]}${originPath}`, {
      method: req.method,
      headers,
      body: body.byteLength === 0 ? undefined : body,
      redirect: 'manual',
    })

    const out = Buffer.from(await upstream.arrayBuffer())
    const outHeaders: Record<string, string> = {}
    upstream.headers.forEach((value, name) => {
      if (!HOP_BY_HOP.has(name)) outHeaders[name] = value
    })

    console.log(`[${options.label}] ${req.method} ${url.pathname} → ${surface} → ${upstream.status}`)
    res.writeHead(upstream.status, outHeaders)
    res.end(out)
  }

  await new Promise<void>((resolve) => server.listen(options.port, '127.0.0.1', resolve))
  return server
}

function header(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return Array.isArray(value) ? value[0] : value
}

async function readBody(req: IncomingMessage): Promise<ArrayBuffer> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(chunk as Buffer)
  const joined = Buffer.concat(chunks)
  const out = new ArrayBuffer(joined.byteLength)
  new Uint8Array(out).set(joined)
  return out
}
