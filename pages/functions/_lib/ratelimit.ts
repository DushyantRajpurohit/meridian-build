/**
 * R29 (free-path substitute) — edge rate limiting, written here rather than configured,
 * because the no-domain path has no zone-level rulesets to configure.
 *
 * WHAT WE COUNT ON, AND WHY IT IS NOT THE CLIENT IP ALONE
 *
 * Meridian is a clinic. The people most likely to book are sitting in its waiting room, on
 * its wifi, behind one NAT — so to an edge counter keyed on client IP they are a single
 * caller hammering the booking endpoint. Set that counter low enough to stop an abuser and
 * you have locked out the entire waiting room to do it; set it high enough for the waiting
 * room and it stops nothing. The default is wrong in both directions at once.
 *
 * So there are two counters and a request has to pass both:
 *
 *   device  sha256(ip | user-agent)   5 per 10 min   one browser on one machine
 *   network ip                       60 per 10 min   the whole waiting room
 *
 * The narrow counter is what actually bites an abuser: a script flooding /book is one device
 * signature however many requests it sends, and it exhausts five in seconds. Twelve genuine
 * patients on the same wifi have twelve different device signatures and never touch it. The
 * wide counter is the backstop for the case the narrow one misses — an attacker who rotates
 * the User-Agent on every request — and it is set high enough that a full waiting room does
 * not reach it.
 *
 * Neither counter is identity. A determined attacker rotates both. That is fine and expected:
 * the job of this file is to keep volume off the expensive path, and the thing that actually
 * decides whether a booking is real is the Turnstile token the origin verifies (R31).
 *
 * HONEST LIMITATION. KV is eventually consistent and read-modify-write here is racy: a burst
 * arriving in parallel can undercount, and a write takes up to a minute to reach other
 * colos. So this is a volume limiter, not a precise quota. Durable Objects are the correct
 * primitive and are the first thing to change if this were real; §11 names KV, so KV is what
 * this uses. In practice a NAT'd waiting room lands in one colo, which is where the counter
 * is most nearly correct.
 */

import type { KeyValueStore } from './store'

export interface RateLimitDecision {
  blocked: boolean
  rule?: string
  retryAfterSec?: number
}

export interface RateLimitRule {
  name: string
  key: string
  limit: number
  windowSec: number
}

export async function enforce(kv: KeyValueStore, rules: readonly RateLimitRule[]): Promise<RateLimitDecision> {
  const now = Date.now()

  for (const rule of rules) {
    const window = Math.floor(now / 1000 / rule.windowSec)
    const storageKey = `rl:${rule.name}:${rule.key}:${window}`

    const current = Number.parseInt((await kv.get(storageKey)) ?? '0', 10)
    const count = Number.isInteger(current) ? current : 0

    if (count >= rule.limit) {
      const windowEnds = (window + 1) * rule.windowSec
      return {
        blocked: true,
        rule: rule.name,
        retryAfterSec: Math.max(1, windowEnds - Math.floor(now / 1000)),
      }
    }

    // Expire a little past the window so a counter cannot outlive the window it counts.
    await kv.put(storageKey, String(count + 1), { expirationTtl: Math.max(60, rule.windowSec * 2) })
  }

  return { blocked: false }
}

/** The booking rules, in the order they should be checked: narrowest first. */
export async function bookingRules(ip: string, userAgent: string): Promise<RateLimitRule[]> {
  return [
    { name: 'device', key: await fingerprint(`${ip}|${userAgent}`), limit: 5, windowSec: 600 },
    { name: 'network', key: await fingerprint(ip), limit: 60, windowSec: 600 },
  ]
}

/**
 * Hashed so the KV namespace does not become a list of patient IP addresses and browser
 * strings sitting in a datastore for a fortnight. The counter works identically on a digest.
 */
async function fingerprint(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return [...new Uint8Array(digest)].slice(0, 16).map((b) => b.toString(16).padStart(2, '0')).join('')
}
