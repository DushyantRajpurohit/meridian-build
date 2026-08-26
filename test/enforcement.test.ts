import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createAdminApp } from '../src/apps/admin'
import { createPartnerApp } from '../src/apps/partner'
import { verifyAccessToken } from '../src/access/verify'
import { AUD_ADMIN, AUD_PARTNER, createFakeTeam, ISSUER, listen, PARTNER_CLIENT_ID, STAFF, type FakeTeam } from './harness'

/**
 * §4 as an executable specification. Each test names the requirement it discharges, so a
 * change that reopens one of these holes fails the suite rather than the review.
 */

let team: FakeTeam
let admin: Awaited<ReturnType<typeof listen>>
let partner: Awaited<ReturnType<typeof listen>>

beforeAll(async () => {
  team = await createFakeTeam()
  admin = await listen(createAdminApp(team.config))
  partner = await listen(createPartnerApp(team.config))
})

afterAll(async () => {
  await admin.close()
  await partner.close()
})

const get = (base: string, path = '/', headers: Record<string, string> = {}) =>
  fetch(`${base}${path}`, { headers, redirect: 'manual' })

describe('R20 — no path reaches a handler without a verified token', () => {
  it('refuses a request with no token at all', async () => {
    const response = await get(admin.url)
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'no_token' })
  })

  it('refuses a malformed token', async () => {
    const response = await get(admin.url, '/', { 'Cf-Access-Jwt-Assertion': 'not.a.jwt' })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'malformed' })
  })

  it('refuses an expired token', async () => {
    const token = await team.mintUser({ expiresInSec: -120 })
    const response = await get(admin.url, '/', { 'Cf-Access-Jwt-Assertion': token })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'expired' })
  })

  it('refuses a token that simply omits exp', async () => {
    const token = await team.mintUser({ omitExp: true })
    const response = await get(admin.url, '/', { 'Cf-Access-Jwt-Assertion': token })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'expired' })
  })

  it('refuses a token from another Cloudflare team', async () => {
    const token = await team.mintUser({ issuer: 'https://someone-else.cloudflareaccess.com' })
    const response = await get(admin.url, '/', { 'Cf-Access-Jwt-Assertion': token })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'wrong_issuer' })
  })

  it('admits a genuine staff token', async () => {
    const token = await team.mintUser()
    const response = await get(admin.url, '/', { 'Cf-Access-Jwt-Assertion': token })
    expect(response.status).toBe(200)
    await expect(response.text()).resolves.toContain(STAFF[0])
  })

  it('refuses a genuine token for someone who is not staff', async () => {
    const token = await team.mintUser({ email: 'stranger@example.com' })
    const response = await get(admin.url, '/', { 'Cf-Access-Jwt-Assertion': token })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'not_on_staff_allowlist' })
  })
})

describe('R17 — header first, cookie as fallback', () => {
  it('accepts the token from the CF_Authorization cookie', async () => {
    const token = await team.mintUser()
    const response = await get(admin.url, '/', { cookie: `foo=bar; CF_Authorization=${token}; baz=qux` })
    expect(response.status).toBe(200)
  })
})

describe('R23 — syntactically valid, wrongly signed', () => {
  it('refuses a token signed by a key the team never published', async () => {
    const token = await team.mintForged()
    const response = await get(admin.url, '/', { 'Cf-Access-Jwt-Assertion': token })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'bad_signature' })
  })
})

describe('R22 — cross-audience confusion', () => {
  it('a partner token passes signature and issuer but fails the pinned aud', async () => {
    const token = await team.mintService()

    // The vulnerable middleware: everything checked except aud. This is what "it works" looks
    // like right up until someone notices that every application in the team shares a signer.
    const withoutAud = await verifyAccessToken(token, {
      jwks: team.config.jwks,
      issuer: ISSUER,
      audience: null,
    })
    expect(withoutAud).toEqual({ kind: 'service', clientId: PARTNER_CLIENT_ID })

    // The same token against the real admin origin, where aud is pinned.
    const response = await get(admin.url, '/', { 'Cf-Access-Jwt-Assertion': token })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'wrong_audience' })
  })

  it('a staff token does not open the partner API either', async () => {
    const token = await team.mintUser({ audience: AUD_ADMIN })
    const response = await get(partner.url, '/v1/results', { 'Cf-Access-Jwt-Assertion': token })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'wrong_audience' })
  })
})

describe('R21 — identity comes from claims, never from a header', () => {
  it('refuses a spoofed identity header on its own', async () => {
    const response = await get(admin.url, '/', { 'Cf-Access-Authenticated-User-Email': 'ceo@meridian.test' })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'no_token' })
  })

  it('ignores the header even when a valid token is present', async () => {
    const token = await team.mintUser({ email: STAFF[1] })
    const response = await get(admin.url, '/api/patients', {
      'Cf-Access-Jwt-Assertion': token,
      'Cf-Access-Authenticated-User-Email': 'ceo@meridian.test',
    })
    expect(response.status).toBe(200)
    const body = (await response.json()) as { viewer: string }
    expect(body.viewer).toBe(STAFF[1])
    expect(body.viewer).not.toBe('ceo@meridian.test')
  })
})

describe('R26/R27/R28 — the machine path', () => {
  it('the partner service token reads results', async () => {
    const token = await team.mintService()
    const response = await get(partner.url, '/v1/results', { 'Cf-Access-Jwt-Assertion': token })
    expect(response.status).toBe(200)
  })

  it('an unknown service client is refused', async () => {
    const token = await team.mintService({ clientId: 'someone-elses-token.access' })
    const response = await get(partner.url, '/v1/results', { 'Cf-Access-Jwt-Assertion': token })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'unknown_service_client' })
  })

  it('R28 — the service token does not open the staff console', async () => {
    // Even minted for the admin audience, so this is not the aud check doing the work.
    const token = await team.mintService({ audience: AUD_ADMIN })
    const response = await get(admin.url, '/', { 'Cf-Access-Jwt-Assertion': token })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'service_principal_on_human_route' })
  })

  it('R27 — a human token does not reach the machine route', async () => {
    const token = await team.mintUser({ audience: AUD_PARTNER })
    const response = await get(partner.url, '/v1/results', { 'Cf-Access-Jwt-Assertion': token })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'not_a_service_principal' })
  })
})

describe('R18 — JWKS cache and key rotation', () => {
  it('caches the key set across requests', async () => {
    const fresh = await createFakeTeam()
    const app = await listen(createAdminApp(fresh.config))
    try {
      const token = await fresh.mintUser()
      for (let i = 0; i < 5; i += 1) {
        expect((await get(app.url, '/', { 'Cf-Access-Jwt-Assertion': token })).status).toBe(200)
      }
      expect(fresh.jwksRequests()).toBe(1)
    } finally {
      await app.close()
    }
  })

  it('an unknown kid forces a refetch, so a rotated key works on the first request', async () => {
    // Floor removed so the forced path is exercised without the test sleeping through it.
    const fresh = await createFakeTeam({ jwks: { minRefreshIntervalMs: 0 } })
    const app = await listen(createAdminApp(fresh.config))
    try {
      expect((await get(app.url, '/', { 'Cf-Access-Jwt-Assertion': await fresh.mintUser() })).status).toBe(200)
      expect(fresh.jwksRequests()).toBe(1)

      // Cloudflare rotates. The cache is still well inside its 15-minute TTL, so only the
      // unseen kid can trigger the refetch — and it does, immediately.
      await fresh.rotateSigningKey()
      expect((await get(app.url, '/', { 'Cf-Access-Jwt-Assertion': await fresh.mintUser() })).status).toBe(200)
      expect(fresh.jwksRequests()).toBe(2)
    } finally {
      await app.close()
    }
  })

  it('the refetch floor holds, so unknown kids cannot amplify requests at Cloudflare', async () => {
    const fresh = await createFakeTeam() // default 10s floor
    const app = await listen(createAdminApp(fresh.config))
    try {
      expect((await get(app.url, '/', { 'Cf-Access-Jwt-Assertion': await fresh.mintUser() })).status).toBe(200)
      expect(fresh.jwksRequests()).toBe(1)

      // Twenty tokens, each labelled with a kid the team has never published — the input
      // that reaches the forced-refetch path. Every one is refused as an unknown key, and
      // between them they cost the certs endpoint nothing.
      for (let i = 0; i < 20; i += 1) {
        const response = await get(app.url, '/', { 'Cf-Access-Jwt-Assertion': await fresh.mintUnknownKid() })
        expect(response.status).toBe(403)
        await expect(response.json()).resolves.toMatchObject({ reason: 'unknown_key' })
      }
      expect(fresh.jwksRequests()).toBe(1)
    } finally {
      await app.close()
    }
  })
})
