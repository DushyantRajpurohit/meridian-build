/**
 * Where each surface lives, and how the Function finds it.
 *
 * On the free path the origin is behind a quick tunnel, whose hostname rotates every time
 * cloudflared restarts. So the box publishes its current URLs to KV on boot
 * (scripts/publish-origins.ts) and this reads them. That rotation is not an inconvenience to
 * work around; §11 nominates it as the operations exercise, and it is the reason there is a
 * lookup here at all rather than a constant.
 */

import type { KeyValueStore } from './store'

export type Surface = 'public' | 'admin' | 'partner'

/**
 * The header the origin stamps on every response, naming the surface that produced it.
 * Declared again in src/config.ts — the two halves are written separately and pinned
 * together by test/edge.test.ts, the same way the edge signature is.
 */
export const ORIGIN_HEADER = 'x-meridian-origin'

export interface Route {
  surface: Surface
  /** Path as the origin should see it, after any prefix is stripped. */
  originPath: string
}

/**
 * One Pages project is one hostname, so the three surfaces are separated by path prefix
 * rather than by the three hostnames the domain path would give them. The prefixes are
 * stripped before forwarding, so each Express app still sees the routes the assignment
 * specifies — `/` and `/book` on the clinic, `/v1/results` on the partner API.
 */
export function route(pathname: string, search: string): Route {
  if (pathname === '/admin' || pathname.startsWith('/admin/')) {
    const stripped = pathname.slice('/admin'.length)
    return { surface: 'admin', originPath: (stripped === '' ? '/' : stripped) + search }
  }
  if (pathname.startsWith('/v1/')) {
    return { surface: 'partner', originPath: pathname + search }
  }
  return { surface: 'public', originPath: pathname + search }
}

/** Cached for the lifetime of an isolate; a rotation costs one cold lookup per isolate. */
const memo = new Map<Surface, string>()

export async function originFor(kv: KeyValueStore, surface: Surface): Promise<string | null> {
  const cached = memo.get(surface)
  if (cached !== undefined) return cached

  const url = await kv.get(`origin:${surface}`)
  if (url === null || url.length === 0) return null

  memo.set(surface, url)
  return url
}

/** Called when the origin stops answering, so a rotation does not need a redeploy. */
export function forget(surface: Surface): void {
  memo.delete(surface)
}
