import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { ORIGIN_HEADER as EDGE_ORIGIN_HEADER } from '../pages/functions/_lib/origin'
import { signForOrigin } from '../pages/functions/_lib/sign'
import { createAdminApp } from '../src/apps/admin'
import { ORIGIN_HEADER as SERVICE_ORIGIN_HEADER } from '../src/config'
import { createPublicApp } from '../src/apps/public'
import { createFakeTeam, listen, type FakeTeam } from './harness'

/**
 * The hop from the Pages Function to the quick tunnel, and R24.
 *
 * These tests import the Function's own signing code rather than reimplementing it, so they
 * also answer a question that would otherwise only be answered in production: whether the
 * Web Crypto HMAC in the Worker and the node:crypto HMAC at the origin agree byte for byte.
 */

let team: FakeTeam
let admin: Awaited<ReturnType<typeof listen>>
let publicSite: Awaited<ReturnType<typeof listen>>

const SECRET = 'edge-secret-for-tests'

beforeAll(async () => {
  team = await createFakeTeam({ requireEdgeSignature: true })
  admin = await listen(createAdminApp(team.config))
  publicSite = await listen(
    createPublicApp(team.config, { verifyTurnstile: async (t) => t === 'good-token' }),
  )
})

afterAll(async () => {
  await admin.close()
  await publicSite.close()
})

/** Exactly what the Pages Function does before it calls fetch(). */
async function asEdge(method: string, pathWithQuery: string, body = '') {
  const bytes = new TextEncoder().encode(body)
  const signature = await signForOrigin(SECRET, method, pathWithQuery, bytes.buffer as ArrayBuffer)
  return {
    'X-Meridian-Timestamp': signature.timestamp,
    'X-Meridian-Nonce': signature.nonce,
    'X-Meridian-Signature': signature.signature,
  }
}

describe('the Function and the origin agree on the signature', () => {
  it('a request signed by the Worker code is accepted by the Node origin', async () => {
    const headers = await asEdge('GET', '/')
    const response = await fetch(`${admin.url}/`, {
      headers: { ...headers, 'Cf-Access-Jwt-Assertion': await team.mintUser() },
    })
    expect(response.status).toBe(200)
  })

  it('carries a signed POST body through unchanged', async () => {
    const body = 'name=Asha&cf-turnstile-response=good-token'
    const response = await fetch(`${publicSite.url}/book`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...(await asEdge('POST', '/book', body)) },
      body,
    })
    expect(response.status).toBe(201)
  })
})

describe('R24 — arriving by any other route', () => {
  it('a request straight to the origin, bypassing the edge entirely, is refused', async () => {
    // This is the trycloudflare URL in the acceptance suite: a public hostname that reaches
    // the application, with no Access application in front of it and no Function to sign.
    const response = await fetch(`${admin.url}/`, {
      headers: { 'Cf-Access-Jwt-Assertion': await team.mintUser() },
    })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'edge_nonce_missing' })
  })

  it('a request through the edge but with no token is refused by the token check', async () => {
    // The canonical <project>.pages.dev hostname: Access is NOT bound to it, so the Function
    // forwards a perfectly signed request carrying no token at all. The signature proves the
    // route and decides nothing; the origin still refuses. This is the whole point of §4.
    const response = await fetch(`${admin.url}/`, { headers: await asEdge('GET', '/') })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'no_token' })
  })

  it('the booking rate limiter cannot be walked around by going direct', async () => {
    const body = 'name=Asha&cf-turnstile-response=good-token'
    const response = await fetch(`${publicSite.url}/book`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    })
    expect(response.status).toBe(403)
  })
})

describe('the edge signature itself', () => {
  it('refuses a body altered after the Function signed it', async () => {
    const headers = await asEdge('POST', '/book', 'name=Asha&cf-turnstile-response=good-token')
    const response = await fetch(`${publicSite.url}/book`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: 'name=Mallory&cf-turnstile-response=good-token',
    })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'edge_bad_signature' })
  })

  it('refuses a signature lifted from one route onto another', async () => {
    // Method and path are inside the signed material precisely so this fails.
    const headers = await asEdge('GET', '/api/patients')
    const response = await fetch(`${publicSite.url}/book`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: 'name=Asha&cf-turnstile-response=good-token',
    })
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({ reason: 'edge_bad_signature' })
  })

  it('refuses a captured request replayed at the origin', async () => {
    const body = 'name=Asha&cf-turnstile-response=good-token'
    const headers = {
      'content-type': 'application/x-www-form-urlencoded',
      ...(await asEdge('POST', '/book', body)),
    }
    expect((await fetch(`${publicSite.url}/book`, { method: 'POST', headers, body })).status).toBe(201)

    const replay = await fetch(`${publicSite.url}/book`, { method: 'POST', headers, body })
    expect(replay.status).toBe(403)
    await expect(replay.json()).resolves.toMatchObject({ reason: 'edge_replayed' })
  })

  it('two identical GETs in the same second are both fine', async () => {
    // The nonce is in the signed material, so replay protection does not misfire on ordinary
    // repeated reads — which is why it is there rather than signing timestamp and body alone.
    const token = await team.mintUser()
    for (let i = 0; i < 2; i += 1) {
      const response = await fetch(`${admin.url}/api/patients`, {
        headers: { ...(await asEdge('GET', '/api/patients')), 'Cf-Access-Jwt-Assertion': token },
      })
      expect(response.status).toBe(200)
    }
  })
})

/**
 * The reaped-lease bug, pinned.
 *
 * The Function decides "the origin answered" by looking for a header the origin sets. The two
 * halves declare that header separately — one in the Worker tree, one in the service tree —
 * so nothing but a test stops them drifting apart, and drift here is silent: the Function
 * would treat every real response as a dead tunnel and serve 502 for everything.
 */
describe('the origin marker', () => {
  it('is spelled the same on both sides of the hop', () => {
    expect(EDGE_ORIGIN_HEADER).toBe(SERVICE_ORIGIN_HEADER)
  })

  it('is what tells a reaped lease apart from a real origin 404', () => {
    // Cloudflare's answer for a quick-tunnel hostname it no longer routes: a 404 with no body
    // and no headers of ours. Status alone cannot distinguish it from the origin 404 below.
    const reaped = new Response(null, { status: 404 })
    const genuine = new Response('{"error":"not_found"}', {
      status: 404,
      headers: { 'content-type': 'application/json', [SERVICE_ORIGIN_HEADER]: 'public' },
    })

    expect(reaped.headers.get(EDGE_ORIGIN_HEADER)).toBeNull()
    expect(genuine.headers.get(EDGE_ORIGIN_HEADER)).toBe('public')
  })
})
