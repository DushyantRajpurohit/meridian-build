import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { checkSignature, ReplayCache } from '../hmac'

/**
 * The origin half of the Pages Function's signature (see pages/functions/_lib/sign.ts).
 *
 * Read that file for why this exists. The short version: on the free path the origin answers
 * on a public `trycloudflare.com` URL, so anything that only the edge is supposed to do —
 * the rate limiter, the filtering rule, the Access application itself — is bypassable by
 * anyone who learns that URL, unless the origin can tell which requests came through the
 * edge. This is how it tells.
 *
 * It is emphatically not authentication. The secret proves a route, not a caller. It runs
 * before requireAccess and never in place of it: a request that is perfectly signed and
 * carries no Access token still gets a 403 from the next middleware along, which is exactly
 * what R24 asks to be demonstrated.
 */
export interface EdgeSignatureOptions {
  secret: string
  windowSec?: number
}

export function requireEdgeSignature(options: EdgeSignatureOptions): RequestHandler {
  const { secret, windowSec = 300 } = options
  const replayCache = new ReplayCache()

  return function edgeGate(req: Request, res: Response, next: NextFunction): void {
    const nonce = header(req.headers['x-meridian-nonce'])
    if (nonce === undefined || nonce.length === 0) {
      deny(res, 'edge_nonce_missing')
      return
    }

    // Rebuilt byte-for-byte from what the Function signed: method, the path it forwarded,
    // the nonce, then the raw body. req.originalUrl is the path as it arrived here, which is
    // the path the Function put in the signature after stripping its surface prefix.
    const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0)
    const head = Buffer.from(`${req.method}\n${req.originalUrl}\n${nonce}\n`, 'utf8')

    const failure = checkSignature({
      secret,
      rawBody: Buffer.concat([head, raw]),
      signature: header(req.headers['x-meridian-signature']),
      timestamp: header(req.headers['x-meridian-timestamp']),
      windowSec,
      replayCache,
    })

    if (failure !== null) {
      console.log(`[edge-gate] ${req.method} ${req.originalUrl} refused: ${failure}`)
      deny(res, `edge_${failure}`)
      return
    }

    next()
  }
}

function header(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value
}

/**
 * 403 rather than 401, so that every way of arriving at this origin without going through
 * the edge produces the same status as arriving without a token. R24's acceptance line
 * expects 403 and gets it whichever of the two checks does the refusing; the `reason` says
 * which, for the log and for the writeup.
 */
function deny(res: Response, reason: string): void {
  res.status(403).json({ error: 'forbidden', reason })
}
