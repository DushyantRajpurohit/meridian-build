import type { Request } from 'express'

/**
 * Every surface takes its body as raw bytes and parses afterwards, because the edge signature
 * and the lab webhook signature are both over the bytes exactly as they arrived. Re-serialising
 * a parsed object changes them — key order, whitespace, number formatting — and the signature
 * stops matching for reasons that look like a key problem and are not.
 */
export function rawBody(req: Request): Buffer {
  return Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0)
}

export function jsonBody(req: Request): unknown {
  const raw = rawBody(req)
  if (raw.length === 0) return undefined
  try {
    return JSON.parse(raw.toString('utf8'))
  } catch {
    return undefined
  }
}

export function formBody(req: Request): URLSearchParams {
  return new URLSearchParams(rawBody(req).toString('utf8'))
}
