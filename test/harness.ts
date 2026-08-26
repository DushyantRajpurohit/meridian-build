import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose'
import { JwksCache, type JwksCacheOptions } from '../src/access/jwks'
import type { MeridianConfig } from '../src/config'

/**
 * A local stand-in for a Zero Trust team: one signing key that the origin trusts, and a
 * second that it has never heard of. Everything R20–R23 asks to be demonstrated can be
 * demonstrated against this without a Cloudflare account, which means the enforcement path
 * has a regression test rather than a one-off screenshot.
 */

export const TEAM_DOMAIN = 'meridian-test.cloudflareaccess.com'
export const ISSUER = `https://${TEAM_DOMAIN}`
export const AUD_ADMIN = 'a'.repeat(64)
export const AUD_PARTNER = 'b'.repeat(64)
export const STAFF = ['dr.okafor@meridian.test', 'nurse.li@meridian.test']
export const PARTNER_CLIENT_ID = 'partner-lab.access'

export interface FakeTeam {
  config: MeridianConfig
  /** A token the origin should accept for the given audience. */
  mintUser: (options?: MintUserOptions) => Promise<string>
  mintService: (options?: MintServiceOptions) => Promise<string>
  /** R23 — correctly formed, signed by a key the team never published. */
  mintForged: (options?: MintUserOptions) => Promise<string>
  /** Signed by an untrusted key and labelled with a kid the team has never published. */
  mintUnknownKid: () => Promise<string>
  jwksRequests: () => number
  rotateSigningKey: () => Promise<void>
}

interface MintUserOptions {
  email?: string
  audience?: string | string[]
  issuer?: string
  expiresInSec?: number
  omitExp?: boolean
}

interface MintServiceOptions {
  clientId?: string
  audience?: string
  expiresInSec?: number
}

export interface FakeTeamOptions {
  /** Turn on the origin's edge-signature gate, which production runs with. */
  requireEdgeSignature?: boolean
  /** Overrides for the cache under test, so R18's floor and TTL can be exercised directly. */
  jwks?: Omit<Partial<JwksCacheOptions>, 'certsUrl' | 'fetchImpl'>
}

export async function createFakeTeam(options: FakeTeamOptions = {}): Promise<FakeTeam> {
  let trusted = await generateKeyPair('RS256', { extractable: true })
  let trustedKid = 'kid-1'
  const untrusted = await generateKeyPair('RS256', { extractable: true })

  let requests = 0

  // The JWKS endpoint, without a socket. JwksCache takes its fetch as a dependency precisely
  // so the cache behaviour in R18 is testable.
  const fetchImpl = (async () => {
    requests += 1
    const jwk: JWK = { ...(await exportJWK(trusted.publicKey)), kid: trustedKid, alg: 'RS256', use: 'sig' }
    return new Response(JSON.stringify({ keys: [jwk] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  }) as unknown as typeof fetch

  const config: MeridianConfig = {
    teamDomain: TEAM_DOMAIN,
    issuer: ISSUER,
    jwks: new JwksCache({ certsUrl: `${ISSUER}/cdn-cgi/access/certs`, fetchImpl, ...options.jwks }),
    audiences: { admin: AUD_ADMIN, partner: AUD_PARTNER },
    staffEmails: STAFF,
    partnerClientIds: [PARTNER_CLIENT_ID],
    edgeHmacSecret: 'edge-secret-for-tests',
    requireEdgeSignature: options.requireEdgeSignature ?? false,
    labWebhookSecret: 'lab-secret-for-tests',
    turnstileSecret: 'turnstile-secret-for-tests',
    turnstileSiteKey: '1x00000000000000000000AA',
    bindHost: '127.0.0.1',
    ports: { public: 0, admin: 0, partner: 0 },
  }

  async function mint(
    key: CryptoKey,
    kid: string,
    claims: Record<string, unknown>,
    options: { issuer?: string; audience?: string | string[]; expiresInSec?: number; omitExp?: boolean },
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000)
    let jwt = new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer(options.issuer ?? ISSUER)
      .setIssuedAt(now)
    if (options.audience !== undefined) jwt = jwt.setAudience(options.audience)
    if (options.omitExp !== true) jwt = jwt.setExpirationTime(now + (options.expiresInSec ?? 3600))
    return jwt.sign(key)
  }

  return {
    config,
    mintUser: (options = {}) =>
      mint(
        trusted.privateKey,
        trustedKid,
        { email: options.email ?? STAFF[0], sub: 'sub-okafor', identity_nonce: 'nonce-1', country: 'IN', type: 'app' },
        { issuer: options.issuer, audience: options.audience ?? AUD_ADMIN, expiresInSec: options.expiresInSec, omitExp: options.omitExp },
      ),
    mintService: (options = {}) =>
      mint(
        trusted.privateKey,
        trustedKid,
        { common_name: options.clientId ?? PARTNER_CLIENT_ID, sub: '', type: 'app' },
        { audience: options.audience ?? AUD_PARTNER, expiresInSec: options.expiresInSec },
      ),
    mintForged: (options = {}) =>
      mint(
        untrusted.privateKey,
        trustedKid, // same kid, so the origin looks up a real key and the signature still fails
        { email: options.email ?? 'ceo@meridian.test', sub: 'sub-forged', type: 'app' },
        { audience: options.audience ?? AUD_ADMIN },
      ),
    mintUnknownKid: () =>
      mint(
        untrusted.privateKey,
        `kid-never-published-${Math.random().toString(36).slice(2, 10)}`,
        { email: 'ceo@meridian.test', sub: 'sub-forged', type: 'app' },
        { audience: AUD_ADMIN },
      ),
    jwksRequests: () => requests,
    rotateSigningKey: async () => {
      trusted = await generateKeyPair('RS256', { extractable: true })
      trustedKid = `kid-${Math.random().toString(36).slice(2, 8)}`
    },
  }
}

/** Start an Express app on an ephemeral loopback port and return its base URL. */
export async function listen(app: import('express').Express): Promise<{ url: string; close: () => Promise<void> }> {
  const { createServer } = await import('node:http')
  const server = createServer(app)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('no port')
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  }
}
