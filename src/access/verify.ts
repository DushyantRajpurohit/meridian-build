import { decodeProtectedHeader, jwtVerify, type JWTPayload } from 'jose'
import type { JwksCache } from './jwks'

/**
 * R19/R20 — the forty lines the assignment is actually about.
 *
 * Everything Access knows about a caller arrives as this token and nothing else. There is no
 * path out of this function that yields a principal without a checked signature, issuer,
 * audience and expiry.
 */

export type AccessFailure =
  | 'no_token'
  | 'malformed'
  | 'bad_algorithm'
  | 'unknown_key'
  | 'bad_signature'
  | 'expired'
  | 'wrong_issuer'
  | 'wrong_audience'
  | 'no_principal'

export class AccessDenied extends Error {
  readonly code: AccessFailure

  constructor(code: AccessFailure, message: string) {
    super(message)
    this.name = 'AccessDenied'
    this.code = code
  }
}

/**
 * R21/R27 — identity is this union and nothing else. A service token has no email, so there
 * is no `email` field on a service principal to accidentally read as one; the type system
 * refuses the confusion rather than a runtime check catching it later.
 */
export type Principal =
  | { kind: 'user'; email: string; subject: string; identityNonce?: string; country?: string }
  | { kind: 'service'; clientId: string }

export interface VerifyOptions {
  jwks: JwksCache
  /** https://<team>.cloudflareaccess.com */
  issuer: string
  /**
   * R19 — the AUD tag of one specific Access application.
   *
   * `null` deliberately skips the audience check and exists only so R22 can show the
   * vulnerable middleware next to the fixed one. Application code passes a string. Nothing
   * outside scripts/cross-audience.ts may pass null.
   */
  audience: string | null
  /** Tolerance for clock drift between the edge and this box. */
  clockToleranceSec?: number
}

export async function verifyAccessToken(token: string, options: VerifyOptions): Promise<Principal> {
  const { jwks, issuer, audience, clockToleranceSec = 30 } = options

  if (token.length === 0) {
    throw new AccessDenied('no_token', 'no token presented')
  }

  // 1. Header. Pin the algorithm before touching a key, so a token claiming `alg: none` or
  //    an HMAC over the public key never reaches the verifier at all.
  let header: ReturnType<typeof decodeProtectedHeader>
  try {
    header = decodeProtectedHeader(token)
  } catch {
    throw new AccessDenied('malformed', 'token is not a well-formed JWS')
  }
  if (header.alg !== 'RS256') {
    throw new AccessDenied('bad_algorithm', `alg ${String(header.alg)} is not accepted`)
  }
  if (typeof header.kid !== 'string') {
    throw new AccessDenied('malformed', 'token header carries no kid')
  }

  // 2. Key, by kid, from the team JWKS.
  let key: Awaited<ReturnType<JwksCache['getKey']>>
  try {
    key = await jwks.getKey(header.kid)
  } catch {
    throw new AccessDenied('unknown_key', `kid ${header.kid} is not published by ${issuer}`)
  }

  // 3. Signature and expiry. jose checks exp and nbf here; the explicit exp check below
  //    covers the case it does not — a token that simply omits exp and never goes stale.
  let payload: JWTPayload
  try {
    ;({ payload } = await jwtVerify(token, key, {
      algorithms: ['RS256'],
      clockTolerance: clockToleranceSec,
    }))
  } catch (error) {
    const code = String((error as { code?: string }).code)
    if (code === 'ERR_JWT_EXPIRED') {
      throw new AccessDenied('expired', 'token has expired')
    }
    throw new AccessDenied('bad_signature', 'signature does not verify against the team JWKS')
  }

  if (typeof payload.exp !== 'number') {
    throw new AccessDenied('expired', 'token carries no exp')
  }

  // 4. Issuer — this team, not merely some Cloudflare team.
  if (payload.iss !== issuer) {
    throw new AccessDenied('wrong_issuer', `iss ${String(payload.iss)} is not ${issuer}`)
  }

  // 5. Audience — R22. Every application in the team is signed by the same key by the same
  //    issuer, so this is the only claim that distinguishes a token minted for the staff
  //    console from one minted for the partner API.
  if (audience !== null) {
    const aud = payload.aud
    const claimed = Array.isArray(aud) ? aud : typeof aud === 'string' ? [aud] : []
    if (!claimed.includes(audience)) {
      throw new AccessDenied('wrong_audience', `aud ${JSON.stringify(aud)} is not ${audience}`)
    }
  }

  return toPrincipal(payload)
}

/**
 * R21 — built from the verified payload only. No header on the request contributes to it.
 */
function toPrincipal(payload: JWTPayload): Principal {
  const email = payload.email
  if (typeof email === 'string' && email.length > 0) {
    return {
      kind: 'user',
      email: email.toLowerCase(),
      subject: typeof payload.sub === 'string' ? payload.sub : '',
      identityNonce: typeof payload.identity_nonce === 'string' ? payload.identity_nonce : undefined,
      country: typeof payload.country === 'string' ? payload.country : undefined,
    }
  }

  // R27 — a service-token assertion has no email. It carries the client id as common_name.
  // It is a principal, just not a person, and it is returned as such rather than as a user
  // with an empty email.
  const commonName = payload.common_name
  if (typeof commonName === 'string' && commonName.length > 0) {
    return { kind: 'service', clientId: commonName }
  }

  throw new AccessDenied('no_principal', 'token names neither a user nor a service')
}
