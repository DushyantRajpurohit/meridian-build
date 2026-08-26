import { createHmac, timingSafeEqual } from 'node:crypto'

/**
 * R32 — the partner lab can do neither SSO nor service tokens: it is an appliance that POSTs
 * results and can be taught one shared secret and nothing else.
 *
 * An Access Bypass policy would be the wrong answer because Bypass does not authenticate
 * anything. It removes the check for a path, and the path is then open to the whole internet;
 * the lab's IP range is the only thing left to scope it by, and that is an ACL, not identity.
 * Signing moves the proof into the request itself, where it is checked by the origin whatever
 * route the request took to get there.
 *
 * The scheme: HMAC-SHA256 over `${timestamp}.${rawBody}`. The timestamp is inside the signed
 * material, so it cannot be moved to widen the window. Comparison is constant-time. Anything
 * outside the window is refused, and a signature already seen inside the window is refused
 * again — a five-minute window alone still leaves five minutes of free replay.
 */

export interface SignatureCheckOptions {
  secret: string
  /** Raw bytes exactly as they arrived. Re-serialising parsed JSON changes the bytes. */
  rawBody: Buffer
  signature: string | undefined
  timestamp: string | undefined
  windowSec?: number
  now?: number
  replayCache?: ReplayCache
}

export type SignatureFailure =
  | 'missing_signature'
  | 'missing_timestamp'
  | 'bad_timestamp'
  | 'stale_timestamp'
  | 'bad_signature'
  | 'replayed'

export function checkSignature(options: SignatureCheckOptions): SignatureFailure | null {
  const { secret, rawBody, signature, timestamp, windowSec = 300, replayCache } = options
  const now = options.now ?? Date.now()

  if (signature === undefined || signature.length === 0) return 'missing_signature'
  if (timestamp === undefined || timestamp.length === 0) return 'missing_timestamp'

  const sentAt = Number.parseInt(timestamp, 10)
  if (!Number.isInteger(sentAt)) return 'bad_timestamp'

  // Absolute skew, so a timestamp from the future is as suspicious as one from the past.
  if (Math.abs(now / 1000 - sentAt) > windowSec) return 'stale_timestamp'

  const expected = sign(secret, timestamp, rawBody)
  if (!constantTimeEquals(signature, expected)) return 'bad_signature'

  // Only after the signature is proven genuine, so the cache cannot be filled with junk.
  if (replayCache !== undefined && !replayCache.remember(expected, now, windowSec)) {
    return 'replayed'
  }

  return null
}

export function sign(secret: string, timestamp: string, rawBody: Buffer): string {
  return createHmac('sha256', secret)
    .update(`${timestamp}.`)
    .update(rawBody)
    .digest('hex')
}

/**
 * Comparison that does not leak how much of the signature was right. Lengths are compared
 * first because timingSafeEqual throws on a mismatch, and a length check on a hex digest of
 * fixed width reveals nothing an attacker does not already know.
 */
export function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}

/** Signatures seen inside the replay window, evicted lazily as they age out. */
export class ReplayCache {
  private readonly seen = new Map<string, number>()

  /** Returns false if this signature has been presented before. */
  remember(signature: string, now: number, windowSec: number): boolean {
    this.evict(now, windowSec)
    if (this.seen.has(signature)) return false
    this.seen.set(signature, now)
    return true
  }

  private evict(now: number, windowSec: number): void {
    const cutoff = now - windowSec * 1000
    for (const [signature, at] of this.seen) {
      if (at < cutoff) this.seen.delete(signature)
    }
  }

  get size(): number {
    return this.seen.size
  }
}
