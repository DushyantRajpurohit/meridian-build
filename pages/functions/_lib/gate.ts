import { bookingRules, enforce } from './ratelimit'
import type { KeyValueStore } from './store'
import { route, type Surface } from './origin'

/**
 * R29 and R30, in one place.
 *
 * The Pages Function calls this, and so does scripts/local-edge.ts, which is the whole point
 * of it being a separate file: a local demonstration that reimplemented these rules would
 * eventually disagree with the deployed ones, and would then be showing a reviewer something
 * that is not true of production.
 */

export interface GateInput {
  method: string
  pathname: string
  search: string
  ip: string
  userAgent: string
}

export type GateResult =
  | { allow: true; surface: Surface; originPath: string }
  | { allow: false; status: number; reason: string; headers?: Record<string, string>; log: string }

export async function gate(store: KeyValueStore, input: GateInput): Promise<GateResult> {
  const { surface, originPath } = route(input.pathname, input.search)
  const booking = surface === 'public' && input.method === 'POST' && input.pathname === '/book'

  if (booking && input.userAgent.trim() === '') {
    // R30 — a booking POST with no User-Agent at all is not a browser that forgot to
    // introduce itself. On a zone this would be a managed challenge, which is better because
    // it lets a false positive prove itself human; the free path has no challenge to issue.
    return {
      allow: false,
      status: 403,
      reason: 'no_user_agent',
      log: `filter: booking with no user-agent from ${input.ip}`,
    }
  }

  if (booking) {
    const decision = await enforce(store, await bookingRules(input.ip, input.userAgent))
    if (decision.blocked) {
      return {
        allow: false,
        status: 429,
        reason: 'too_many_requests',
        headers: { 'retry-after': String(decision.retryAfterSec ?? 60) },
        log: `rate limit: ${String(decision.rule)} rule tripped by ${input.ip}`,
      }
    }
  }

  return { allow: true, surface, originPath }
}
