import { spawn, type ChildProcess } from 'node:child_process'
import { closeSync, openSync, readFileSync, unlinkSync, writeSync } from 'node:fs'

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
const PROBE_TIMEOUT_MS = 15_000
const FAILURES_BEFORE_RESTART = 3
const failures = new Map<string, number>()

// A URL that answers whenever this box has working DNS and egress, and is not one of ours.
// Its only job is to tell "this box is offline" apart from "every lease was reaped at once".
const UPLINK_PROBE_URL = 'https://cloudflare.com/cdn-cgi/trace'

// Exactly one supervisor may own these three surfaces. Two of them publish to the same three
// KV keys, so the Function follows whichever wrote last while six connectors run and the
// other three hostnames are orphaned — live processes serving a URL nothing points at. I ran
// two by accident and it looked, from outside, exactly like a flaky tunnel.
const LOCK_PATH = '/tmp/meridian-publish-origins.lock'
acquireLock()

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

  const live = SURFACES.filter((surface) => published.has(surface.name))
  if (live.length === 0) return

  const results = await Promise.all(
    live.map(async (surface) => ({
      surface,
      ok: await answers(published.get(surface.name) as string),
    })),
  )

  // When EVERY surface fails in the same round there are two very different causes, and the
  // first version of this guard assumed the wrong one. It read a total failure as this box's
  // uplink dropping and waited it out, because rotating three hostnames over a ten-second
  // hotspot blip turns a blip into a real outage.
  //
  // But quick-tunnel leases are handed out together and expire together, so all three dying
  // at the same instant is the EXPECTED failure on this path, not the anomaly — and the guard
  // written to prevent flapping is precisely what let the system stay dark. It sat through
  // the reap logging "local network fault" while nothing was wrong with the network.
  //
  // So ask something that is not ours. If the control probe fails too, the box is offline and
  // rotating would accomplish nothing anyway. If it answers, our hostnames are gone and the
  // correlation is evidence rather than a reason to wait.
  //
  // (The earlier bug here was different and is fixed in `answers`: the first version probed
  // without consuming response bodies, which in Node keeps the socket checked out, so later
  // probes timed out and the supervisor diagnosed its own leak as a dead tunnel.)
  if (results.every((result) => !result.ok)) {
    if (!(await answers(UPLINK_PROBE_URL))) {
      console.error(`[probe] all ${String(live.length)} surfaces unreachable and the control probe failed too — this box is offline, not rotating`)
      return
    }
    console.error(`[probe] all ${String(live.length)} surfaces unreachable while the uplink is fine — the leases were reaped together`)
  }

  for (const { surface, ok } of results) {
    if (ok) {
      failures.set(surface.name, 0)
      continue
    }

    const count = (failures.get(surface.name) ?? 0) + 1
    failures.set(surface.name, count)
    console.error(`[${surface.name}] probe failed (${String(count)}/${String(FAILURES_BEFORE_RESTART)})`)
    if (count < FAILURES_BEFORE_RESTART) continue

    console.error(`[${surface.name}] hostname is gone, rebuilding the connector`)
    failures.set(surface.name, 0)
    // Killing it is the restart: the exit handler owns respawning and republishing, so
    // there is exactly one code path that starts a tunnel.
    children.get(surface.name)?.kill('SIGTERM')
  }
}

async function answers(url: string): Promise<boolean> {
  try {
    const response = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) })
    // Not optional. An unread body leaves the socket checked out of undici's pool, so the
    // next probe against the same host waits for a connection that never frees and times out.
    // The supervisor then diagnoses its own leak as a dead tunnel and rebuilds a healthy one.
    await response.body?.cancel()
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
  releaseLock()
  process.exit(0)
}

function acquireLock(): void {
  // Two passes: the second one only runs after a stale lock has been cleared.
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const fd = openSync(LOCK_PATH, 'wx')
      writeSync(fd, String(process.pid))
      closeSync(fd)
      return
    } catch {
      // The lock exists. It is only meaningful if the process named in it is still running —
      // a supervisor killed with SIGKILL leaves the file behind, and refusing to start for a
      // pid that died a week ago would be worse than the race it prevents.
      let owner = 0
      try {
        owner = Number(readFileSync(LOCK_PATH, 'utf8').trim())
      } catch {
        continue
      }
      if (Number.isInteger(owner) && owner > 0 && running(owner)) {
        console.error(`publish-origins: pid ${String(owner)} is already supervising these tunnels (${LOCK_PATH}) — refusing to start a second one`)
        process.exit(3)
      }
      console.error(`publish-origins: clearing a stale lock from pid ${String(owner)}`)
      try {
        unlinkSync(LOCK_PATH)
      } catch {
        // Someone else cleared it first; the next pass will take it or lose fairly.
      }
    }
  }
  console.error('publish-origins: could not take the lock')
  process.exit(3)
}

function releaseLock(): void {
  try {
    // Only ours. If a stale-lock sweep handed ownership to someone else while we were
    // running, deleting their lock would re-open the exact race the lock exists to close.
    if (readFileSync(LOCK_PATH, 'utf8').trim() === String(process.pid)) unlinkSync(LOCK_PATH)
  } catch {
    // Already gone.
  }
}

function running(pid: number): boolean {
  try {
    // Signal 0 checks for existence without delivering anything. EPERM means it exists and
    // belongs to another user, which still counts as running.
    process.kill(pid, 0)
    return true
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM'
  }
}

function requireEnv(name: string): string {
  const value = process.env[name]
  if (value === undefined || value.length === 0) {
    console.error(`${name} is not set`)
    process.exit(2)
  }
  return value
}
