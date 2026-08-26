import { spawn, type ChildProcess } from 'node:child_process'

/**
 * §11 nominates this as the operations exercise, and it is a fair one: a quick tunnel's
 * hostname is randomly assigned at start and changes every time cloudflared restarts. With no
 * zone there is no stable DNS record to point at the box, so the box has to announce where it
 * currently is.
 *
 * This supervises one quick tunnel per surface, reads the assigned hostname out of
 * cloudflared's own output, writes it to the KV namespace the Pages Function reads, and does
 * it again on every restart. The Function caches per isolate and drops that cache on a
 * connection failure, so a rotation costs one failed request rather than a redeploy.
 *
 * What this arrangement is NOT is a substitute for a named tunnel. It has no stable hostname,
 * no ingress table and no credentials file — three connectors cannot serve one tunnel, so
 * R10's failover exercise is not available on this path. Named tunnels are what the domain
 * path buys, and that is the honest cost of the free route.
 *
 *   CF_ACCOUNT_ID=… CF_KV_NAMESPACE_ID=… CF_API_TOKEN=… pnpm tsx scripts/publish-origins.ts
 */

const SURFACES = [
  { name: 'public', port: Number(process.env.PORT_PUBLIC ?? 3000) },
  { name: 'admin', port: Number(process.env.PORT_ADMIN ?? 3001) },
  { name: 'partner', port: Number(process.env.PORT_PARTNER ?? 3002) },
] as const

const accountId = requireEnv('CF_ACCOUNT_ID')
const namespaceId = requireEnv('CF_KV_NAMESPACE_ID')
// Scoped to Workers KV Storage:Edit on one namespace, and nothing else. See README §R38.
const apiToken = requireEnv('CF_API_TOKEN')

const QUICK_TUNNEL_URL = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/

const children = new Map<string, ChildProcess>()
let stopping = false

for (const surface of SURFACES) start(surface.name, surface.port)

process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)

function start(name: string, port: number): void {
  // R7 trap — the literal IPv4 loopback, never `localhost`. If Node binds IPv4-only and
  // localhost resolves to ::1 first, cloudflared reports an intermittent 502 that looks
  // exactly like a Cloudflare fault and is not one.
  const child = spawn('cloudflared', ['tunnel', '--url', `http://127.0.0.1:${port}`], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  children.set(name, child)

  let published = false
  const scan = (chunk: Buffer): void => {
    if (published) return
    const found = QUICK_TUNNEL_URL.exec(chunk.toString('utf8'))
    if (found === null) return
    published = true
    void publish(name, found[0])
  }

  child.stdout?.on('data', scan)
  child.stderr?.on('data', scan)

  child.on('exit', (code) => {
    children.delete(name)
    if (stopping) return
    console.error(`[${name}] cloudflared exited (${String(code)}), restarting in 3s`)
    setTimeout(() => start(name, port), 3_000)
  })
}

async function publish(surface: string, url: string): Promise<void> {
  const endpoint = `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/origin:${surface}`

  try {
    const response = await fetch(endpoint, {
      method: 'PUT',
      headers: { authorization: `Bearer ${apiToken}`, 'content-type': 'text/plain' },
      body: url,
    })
    if (!response.ok) {
      console.error(`[${surface}] KV write failed: ${response.status} ${await response.text()}`)
      return
    }
    console.log(`[${surface}] ${url} → origin:${surface}`)
  } catch (error) {
    console.error(`[${surface}] KV write failed: ${String(error)}`)
  }
}

function shutdown(): void {
  stopping = true
  for (const child of children.values()) child.kill('SIGTERM')
  process.exit(0)
}

function requireEnv(name: string): string {
  const value = process.env[name]
  if (value === undefined || value.length === 0) {
    console.error(`${name} is not set`)
    process.exit(2)
  }
  return value
}
