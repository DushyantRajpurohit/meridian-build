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
const published = new Map<string, string>()
let stopping = false

// How often to ask whether the published hostname still answers, and how many consecutive
// failures are needed before the connector is torn down and rebuilt.
const PROBE_INTERVAL_MS = 60_000
const PROBE_TIMEOUT_MS = 10_000
const FAILURES_BEFORE_RESTART = 2
const failures = new Map<string, number>()

for (const surface of SURFACES) start(surface.name, surface.port)

const probeTimer = setInterval(() => void probeAll(), PROBE_INTERVAL_MS)
probeTimer.unref?.()

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

  let announced = false
  const scan = (chunk: Buffer): void => {
    if (announced) return
    const found = QUICK_TUNNEL_URL.exec(chunk.toString('utf8'))
    if (found === null) return
    announced = true
    published.set(name, found[0])
    failures.set(name, 0)
    void publish(name, found[0])
  }

  child.stdout?.on('data', scan)
  child.stderr?.on('data', scan)

  child.on('exit', (code) => {
    children.delete(name)
    published.delete(name)
    if (stopping) return
    console.error(`[${name}] cloudflared exited (${String(code)}), restarting in 3s`)
    setTimeout(() => start(name, port), 3_000)
  })
}

/**
 * The failure this exists for is the one that actually happened, and it is not the one the
 * exit handler above catches.
 *
 * A quick tunnel's hostname is leased, not owned. Cloudflare reaped all three of mine while
 * every `cloudflared` process stayed alive and reported nothing: the connectors were holding
 * connections for names that no longer resolved. The public hostname returned 530 for as long
 * as nobody looked. A supervisor that only watches for process exit cannot see this, because
 * the process never exits.
 *
 * So the probe asks the question from outside instead. It fetches the hostname it published
 * and cares about *which kind* of failure comes back:
 *
 *   - any HTTP status, including 403 — the tunnel is fine. The origin refusing an unsigned
 *     request (R19) is a healthy path end to end, so a status code is the success condition.
 *   - a thrown fetch — DNS or connect failed, which means the hostname is gone.
 *
 * Two consecutive failures tear the connector down; the exit handler restarts it and the new
 * hostname is republished to KV. One failure is not enough: a hotspot on a train drops packets,
 * and rebuilding a healthy tunnel because of one timeout is its own outage.
 */
async function probeAll(): Promise<void> {
  if (stopping) return

  await Promise.all(
    SURFACES.map(async (surface) => {
      const url = published.get(surface.name)
      if (url === undefined) return

      if (await answers(url)) {
        failures.set(surface.name, 0)
        return
      }

      const count = (failures.get(surface.name) ?? 0) + 1
      failures.set(surface.name, count)
      console.error(`[${surface.name}] probe failed (${String(count)}/${String(FAILURES_BEFORE_RESTART)}) ${url}`)
      if (count < FAILURES_BEFORE_RESTART) return

      console.error(`[${surface.name}] hostname is gone, rebuilding the connector`)
      failures.set(surface.name, 0)
      // Killing it is the restart: the exit handler owns respawning and republishing, so
      // there is exactly one code path that starts a tunnel.
      children.get(surface.name)?.kill('SIGTERM')
    }),
  )
}

async function answers(url: string): Promise<boolean> {
  try {
    await fetch(url, { method: 'GET', signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) })
    return true
  } catch {
    return false
  }
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
  clearInterval(probeTimer)
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
