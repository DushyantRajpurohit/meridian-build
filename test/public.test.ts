import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createPublicApp } from '../src/apps/public'
import { sign } from '../src/hmac'
import { createFakeTeam, listen, type FakeTeam } from './harness'

let team: FakeTeam
let app: Awaited<ReturnType<typeof listen>>
/** Records what the origin asked Cloudflare, so "was it actually verified" is answerable. */
const verified: string[] = []

beforeAll(async () => {
  team = await createFakeTeam()
  app = await listen(
    createPublicApp(team.config, {
      verifyTurnstile: async (token) => {
        verified.push(token)
        return token === 'a-token-cloudflare-would-accept'
      },
    }),
  )
})

afterAll(async () => {
  await app.close()
})

const book = (body: string) =>
  fetch(`${app.url}/book`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  })

describe('R31 — Turnstile is verified server-side', () => {
  it('refuses a booking with no Turnstile token', async () => {
    const response = await book('name=x')
    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toMatchObject({ error: 'turnstile_missing' })
  })

  it('refuses a booking whose token Cloudflare does not accept', async () => {
    const response = await book('name=x&cf-turnstile-response=obviously-not-a-real-token')
    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toMatchObject({ error: 'turnstile_failed' })
    // The point of the requirement: the token reached the verifier rather than being decor.
    expect(verified).toContain('obviously-not-a-real-token')
  })

  it('accepts a booking with a token Cloudflare accepts', async () => {
    const response = await book('name=Asha&reason=cough&cf-turnstile-response=a-token-cloudflare-would-accept')
    expect(response.status).toBe(201)
    await expect(response.json()).resolves.toMatchObject({ name: 'Asha' })
  })
})

describe('R32 — the lab webhook', () => {
  const body = JSON.stringify({ patient: 'A. Rao', panel: 'CBC', value: 'normal' })

  const post = (headers: Record<string, string>, payload = body) =>
    fetch(`${app.url}/hooks/lab`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: payload })

  const signed = (payload = body, at = Math.floor(Date.now() / 1000)) => ({
    'X-Timestamp': String(at),
    'X-Signature': sign(team.config.labWebhookSecret, String(at), Buffer.from(payload)),
  })

  it('accepts a correctly signed, fresh delivery', async () => {
    const response = await post(signed())
    expect(response.status).toBe(202)
  })

  it('refuses an unsigned delivery', async () => {
    const response = await post({})
    expect(response.status).toBe(401)
    await expect(response.json()).resolves.toMatchObject({ reason: 'missing_signature' })
  })

  it('refuses a body that changed after signing', async () => {
    const headers = signed()
    const response = await post(headers, JSON.stringify({ patient: 'A. Rao', panel: 'CBC', value: 'ABNORMAL' }))
    expect(response.status).toBe(401)
    await expect(response.json()).resolves.toMatchObject({ reason: 'bad_signature' })
  })

  it('refuses a delivery from outside the replay window', async () => {
    const response = await post(signed(body, Math.floor(Date.now() / 1000) - 600))
    expect(response.status).toBe(401)
    await expect(response.json()).resolves.toMatchObject({ reason: 'stale_timestamp' })
  })

  it('refuses a timestamp moved forward to widen the window', async () => {
    // The timestamp is inside the signed material, so rewriting it invalidates the signature
    // rather than buying the attacker another five minutes.
    const at = Math.floor(Date.now() / 1000) - 600
    const response = await post({
      'X-Timestamp': String(Math.floor(Date.now() / 1000)),
      'X-Signature': sign(team.config.labWebhookSecret, String(at), Buffer.from(body)),
    })
    expect(response.status).toBe(401)
    await expect(response.json()).resolves.toMatchObject({ reason: 'bad_signature' })
  })

  it('refuses a captured delivery replayed inside the window', async () => {
    const headers = signed(JSON.stringify({ patient: 'B. Singh', panel: 'LFT', value: 'normal' }))
    const payload = JSON.stringify({ patient: 'B. Singh', panel: 'LFT', value: 'normal' })
    expect((await post(headers, payload)).status).toBe(202)

    const replay = await post(headers, payload)
    expect(replay.status).toBe(401)
    await expect(replay.json()).resolves.toMatchObject({ reason: 'replayed' })
  })
})
