import type { NextFunction, Request, RequestHandler, Response } from 'express'
import { AccessDenied, verifyAccessToken, type Principal, type VerifyOptions } from './verify'

declare global {
  namespace Express {
    interface Request {
      /** Set only by requireAccess(), only from verified claims. */
      principal?: Principal
    }
  }
}

/**
 * R21 — headers an upstream is allowed to assert, and that therefore anything reaching the
 * origin can also assert. Access sets these for convenience; they are not evidence. They are
 * deleted on the way in so that no handler, logger or template further down can read one and
 * mistake it for identity.
 */
const FORGEABLE_IDENTITY_HEADERS = [
  'cf-access-authenticated-user-email',
  'cf-access-authenticated-user-id',
  'cf-access-user',
  'x-forwarded-user',
  'x-forwarded-email',
]

export interface AccessMiddlewareOptions extends Omit<VerifyOptions, 'audience'> {
  /** R19 — the AUD tag of this one application. Required; there is no default. */
  audience: string
  /** Called on every decision, for the R41 audit trail. */
  onDecision?: (event: AccessDecision) => void
}

export interface AccessDecision {
  allowed: boolean
  reason: string
  principal?: Principal
  method: string
  path: string
  host: string
}

/**
 * R17/R20 — the only door. Every route that is not deliberately public sits behind this, and
 * there is no branch in it that calls next() without a principal from verifyAccessToken.
 */
export function requireAccess(options: AccessMiddlewareOptions): RequestHandler {
  const { audience, jwks, issuer, clockToleranceSec, onDecision } = options

  return function accessGate(req: Request, res: Response, next: NextFunction): void {
    for (const header of FORGEABLE_IDENTITY_HEADERS) {
      delete req.headers[header]
    }

    const token = readToken(req)

    verifyAccessToken(token, { jwks, issuer, audience, clockToleranceSec }).then(
      (principal) => {
        req.principal = principal
        onDecision?.({
          allowed: true,
          reason: 'verified',
          principal,
          method: req.method,
          path: req.path,
          host: req.hostname,
        })
        next()
      },
      (error: unknown) => {
        const reason = error instanceof AccessDenied ? error.code : 'verification_error'
        onDecision?.({
          allowed: false,
          reason,
          method: req.method,
          path: req.path,
          host: req.hostname,
        })
        // R20 — every failure mode is the same 403. Missing, malformed, expired, wrongly
        // signed and wrong-audience are one answer to the caller and four different lines in
        // the log, because telling an attacker which check failed is free help.
        deny(res, reason)
      },
    )
  }
}

/** R17 — header first, then the cookie the browser carries after an Access login. */
function readToken(req: Request): string {
  const header = req.headers['cf-access-jwt-assertion']
  if (typeof header === 'string' && header.length > 0) return header

  const cookies = req.headers.cookie
  if (typeof cookies !== 'string') return ''

  for (const pair of cookies.split(';')) {
    const eq = pair.indexOf('=')
    if (eq === -1) continue
    if (pair.slice(0, eq).trim() === 'CF_Authorization') {
      return decodeURIComponent(pair.slice(eq + 1).trim())
    }
  }
  return ''
}

function deny(res: Response, reason: string): void {
  res.status(403).json({ error: 'forbidden', reason })
}

/**
 * R27 — a guard for handlers that assume a person. The service principal does not fall
 * through into them; it is refused here with its own reason, and the human path is untouched.
 */
export function requireUser(allowlist?: readonly string[]): RequestHandler {
  const allowed = allowlist?.map((email) => email.toLowerCase())

  return function userGate(req: Request, res: Response, next: NextFunction): void {
    const principal = req.principal
    if (principal === undefined) {
      // Unreachable if the router is wired correctly; a 403 rather than a crash if it is not.
      deny(res, 'no_principal')
      return
    }
    if (principal.kind !== 'user') {
      // R28 — the partner's service token is a valid Access token. It is simply not a member
      // of staff, and the origin says so even when edge policy already should have.
      deny(res, 'service_principal_on_human_route')
      return
    }
    if (allowed !== undefined && !allowed.includes(principal.email)) {
      deny(res, 'not_on_staff_allowlist')
      return
    }
    next()
  }
}

/** The mirror of requireUser, for routes only the partner's machine should reach. */
export function requireService(allowedClientIds?: readonly string[]): RequestHandler {
  return function serviceGate(req: Request, res: Response, next: NextFunction): void {
    const principal = req.principal
    if (principal === undefined || principal.kind !== 'service') {
      deny(res, 'not_a_service_principal')
      return
    }
    if (allowedClientIds !== undefined && !allowedClientIds.includes(principal.clientId)) {
      deny(res, 'unknown_service_client')
      return
    }
    next()
  }
}
