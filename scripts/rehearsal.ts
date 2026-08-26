import { createServer } from 'node:http'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { JwksCache } from '../src/access/jwks'
import { createAdminApp } from '../src/apps/admin'
import { createPartnerApp } from '../src/apps/partner'
import { createPublicApp } from '../src/apps/public'
import type { MeridianConfig } from '../src/config'
import { sign } from '../src/hmac'
import { signForOrigin } from '../pages/functions/_lib/sign'
import { startLocalEdge } from './local-edge'

/**
 * A local dress rehearsal of the assignment's acceptance suite.
 *
 * Everything Cloudflare would supply is stood up here instead: a JWKS endpoint on loopback
 * serving a key pair generated in this process, and a signer that does what the Pages
 * Function does. Everything else is the real thing — the real JwksCache fetching over real
 * HTTP, the real middleware, the real Express apps on the real ports, driven over real
 * sockets.
 *
 * What it cannot rehearse: R29/R30 (they live in the Function, against KV), the Access login
 * redirect, and anything in §2, §7, §8 or §9. Those need an account.
 *
 *   pnpm tsx scripts/rehearsal.ts           run the checks and exit
 *   pnpm tsx scripts/rehearsal.ts --serve   leave it running and print tokens to curl with
 */

const JWKS_PORT = 8790
const ISSUER = `http://127.0.0.1:${JWKS_PORT}`
const AUD_ADMIN = 'admin-application-audience-tag-0000000000000000000000000000'
const AUD_PARTNER = 'partner-application-audience-tag-00000000000000000000000000'
const STAFF = ['dr.okafor@meridian.test', 'nurse.li@meridian.test']
const PARTNER_CLIENT_ID = 'partner-lab.access'
const EDGE_SECRET = 'rehearsal-edge-secret'
const LAB_SECRET = 'rehearsal-lab-secret'
const KID = 'rehearsal-kid-1'

const trusted = await generateKeyPair('RS256', { extractable: true })
const untrusted = await generateKeyPair('RS256', { extractable: true })

// The team JWKS, over real HTTP, so JwksCache does its real job rather than a stubbed one.
const jwksServer = createServer(async (req, res) => {
  if (req.url !== '/cdn-cgi/access/certs') {
    res.writeHead(404).end()
    return
  }
  const jwk = { ...(await exportJWK(trusted.publicKey)), kid: KID, alg: 'RS256', use: 'sig' }
  res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ keys: [jwk] }))
})
await new Promise<void>((resolve) => jwksServer.listen(JWKS_PORT, '127.0.0.1', resolve))

const config: MeridianConfig = {
  teamDomain: `127.0.0.1:${JWKS_PORT}`,
  issuer: ISSUER,
  jwks: new JwksCache({ certsUrl: `${ISSUER}/cdn-cgi/access/certs` }),
  audiences: { admin: AUD_ADMIN, partner: AUD_PARTNER },
  staffEmails: STAFF,
  partnerClientIds: [PARTNER_CLIENT_ID],
  edgeHmacSecret: EDGE_SECRET,
  requireEdgeSignature: true,
  labWebhookSecret: LAB_SECRET,
  turnstileSecret: 'rehearsal-turnstile-secret-that-cloudflare-will-reject',
  bindHost: '127.0.0.1',
  ports: { public: 3000, admin: 3001, partner: 3002 },
}

const apps = [
  { name: 'public', port: 3000, app: createPublicApp(config) },
  { name: 'admin', port: 3001, app: createAdminApp(config) },
  { name: 'partner', port: 3002, app: createPartnerApp(config) },
]
for (const { app, port } of apps) {
  await new Promise<void>((resolve) => {
    app.listen(port, config.bindHost, resolve)
  })
}

const PUBLIC = `http://127.0.0.1:3000`
const ADMIN = `http://127.0.0.1:3001`
const PARTNER = `http://127.0.0.1:3002`

async function mint(
  key: CryptoKey,
  claims: Record<string, unknown>,
  opts: { aud: string; iss?: string; expiresInSec?: number },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuer(opts.iss ?? ISSUER)
    .setAudience(opts.aud)
    .setIssuedAt(now)
    .setExpirationTime(now + (opts.expiresInSec ?? 3600))
    .sign(key)
}

const staffToken = await mint(trusted.privateKey, { email: STAFF[0], sub: 's1', type: 'app' }, { aud: AUD_ADMIN })
const partnerToken = await mint(trusted.privateKey, { common_name: PARTNER_CLIENT_ID, sub: '', type: 'app' }, { aud: AUD_PARTNER })
const forgedToken = await mint(untrusted.privateKey, { email: 'ceo@meridian.test', sub: 'x', type: 'app' }, { aud: AUD_ADMIN })
const expiredToken = await mint(trusted.privateKey, { email: STAFF[0], sub: 's1', type: 'app' }, { aud: AUD_ADMIN, expiresInSec: -120 })
// Deliberately minted FOR the staff console, so the aud check cannot be what refuses it.
const serviceOnAdminAud = await mint(trusted.privateKey, { common_name: PARTNER_CLIENT_ID, sub: '', type: 'app' }, { aud: AUD_ADMIN })

/** What the Pages Function adds to every request it forwards. */
async function edge(method: string, path: string, body = ''): Promise<Record<string, string>> {
  const bytes = new TextEncoder().encode(body)
  const s = await signForOrigin(EDGE_SECRET, method, path, bytes.buffer as ArrayBuffer)
  return {
    'X-Meridian-Timestamp': s.timestamp,
    'X-Meridian-Nonce': s.nonce,
    'X-Meridian-Signature': s.signature,
  }
}

interface Check {
  ref: string
  what: string
  expect: number
  run: () => Promise<Response>
}

const checks: Check[] = [
  {
    ref: 'R20', what: 'no token, through the edge', expect: 403,
    run: async () => fetch(`${ADMIN}/`, { headers: await edge('GET', '/') }),
  },
  {
    ref: 'R20', what: 'malformed token', expect: 403,
    run: async () => fetch(`${ADMIN}/`, { headers: { ...(await edge('GET', '/')), 'Cf-Access-Jwt-Assertion': 'not.a.jwt' } }),
  },
  {
    ref: 'R20', what: 'expired token', expect: 403,
    run: async () => fetch(`${ADMIN}/`, { headers: { ...(await edge('GET', '/')), 'Cf-Access-Jwt-Assertion': expiredToken } }),
  },
  {
    ref: 'R23', what: 'forged signature, real kid', expect: 403,
    run: async () => fetch(`${ADMIN}/`, { headers: { ...(await edge('GET', '/')), 'Cf-Access-Jwt-Assertion': forgedToken } }),
  },
  {
    ref: 'R22', what: 'token minted for the partner API', expect: 403,
    run: async () => fetch(`${ADMIN}/`, { headers: { ...(await edge('GET', '/')), 'Cf-Access-Jwt-Assertion': partnerToken } }),
  },
  {
    ref: 'R21', what: 'spoofed identity header alone', expect: 403,
    run: async () => fetch(`${ADMIN}/`, {
      headers: { ...(await edge('GET', '/')), 'Cf-Access-Authenticated-User-Email': 'ceo@meridian.test' },
    }),
  },
  {
    ref: 'R24', what: 'straight to the origin, no edge signature', expect: 403,
    run: async () => fetch(`${ADMIN}/`, { headers: { 'Cf-Access-Jwt-Assertion': staffToken } }),
  },
  {
    ref: 'R24', what: 'straight to the origin, booking endpoint', expect: 403,
    run: async () => fetch(`${PUBLIC}/book`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'name=x&cf-turnstile-response=y',
    }),
  },
  {
    ref: 'R26', what: 'service token reads the partner API', expect: 200,
    run: async () => fetch(`${PARTNER}/v1/results`, {
      headers: { ...(await edge('GET', '/v1/results')), 'Cf-Access-Jwt-Assertion': partnerToken },
    }),
  },
  {
    ref: 'R28', what: 'service token on the staff console, scoped to it', expect: 403,
    run: async () => fetch(`${ADMIN}/`, { headers: { ...(await edge('GET', '/')), 'Cf-Access-Jwt-Assertion': serviceOnAdminAud } }),
  },
  {
    ref: 'R27', what: 'staff token on the machine-only partner route', expect: 403,
    run: async () => fetch(`${PARTNER}/v1/results`, {
      headers: {
        ...(await edge('GET', '/v1/results')),
        'Cf-Access-Jwt-Assertion': await mint(trusted.privateKey, { email: STAFF[0], sub: 's1', type: 'app' }, { aud: AUD_PARTNER }),
      },
    }),
  },
  {
    // The trap in full: a genuine token AND a spoofed header naming someone else. The
    // console must render the token's email. The REASON column below is the viewer it
    // actually reported.
    ref: 'R21', what: 'valid token + header claiming ceo@meridian.test', expect: 200,
    run: async () => fetch(`${ADMIN}/api/patients`, {
      headers: {
        ...(await edge('GET', '/api/patients')),
        'Cf-Access-Jwt-Assertion': staffToken,
        'Cf-Access-Authenticated-User-Email': 'ceo@meridian.test',
      },
    }),
  },
  {
    ref: 'R31', what: 'booking with a junk Turnstile token', expect: 400,
    run: async () => {
      const body = 'name=x&cf-turnstile-response=obviously-not-a-real-token'
      return fetch(`${PUBLIC}/book`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', ...(await edge('POST', '/book', body)) },
        body,
      })
    },
  },
  {
    ref: 'OK', what: 'genuine staff token reaches the console', expect: 200,
    run: async () => fetch(`${ADMIN}/`, { headers: { ...(await edge('GET', '/')), 'Cf-Access-Jwt-Assertion': staffToken } }),
  },
]

// R32 needs two requests: one accepted, the same one replayed.
const labBody = JSON.stringify({ patient: 'A. Rao', panel: 'CBC', value: 'normal' })
const labTs = Math.floor(Date.now() / 1000).toString()
const labSig = sign(LAB_SECRET, labTs, Buffer.from(labBody))
const labHeaders = { 'content-type': 'application/json', 'X-Timestamp': labTs, 'X-Signature': labSig }

checks.push(
  {
    ref: 'R32', what: 'signed webhook delivery', expect: 202,
    run: async () => fetch(`${PUBLIC}/hooks/lab`, {
      method: 'POST',
      headers: { ...labHeaders, ...(await edge('POST', '/hooks/lab', labBody)) },
      body: labBody,
    }),
  },
  {
    ref: 'R32', what: 'the same delivery replayed', expect: 401,
    run: async () => fetch(`${PUBLIC}/hooks/lab`, {
      method: 'POST',
      headers: { ...labHeaders, ...(await edge('POST', '/hooks/lab', labBody)) },
      body: labBody,
    }),
  },
)

const results: { check: Check; status: number; reason: string; ok: boolean }[] = []
for (const check of checks) {
  const response = await check.run()
  const reason = await reasonOf(response)
  results.push({ check, status: response.status, reason, ok: response.status === check.expect })
}

console.log()
console.log('  REF    EXPECT  GOT   REASON                              CHECK')
console.log('  ' + '-'.repeat(90))

let failed = 0
for (const { check, status, reason, ok } of results) {
  if (!ok) failed += 1
  console.log(
    `  ${check.ref.padEnd(6)} ${String(check.expect).padEnd(7)} ${String(status).padEnd(5)} ${reason.padEnd(35)} ${ok ? '' : 'FAIL  '}${check.what}`,
  )
}

console.log()
console.log(failed === 0 ? `  ${checks.length}/${checks.length} as expected.` : `  ${failed} of ${checks.length} did not match.`)
console.log()

async function reasonOf(response: Response): Promise<string> {
  const type = response.headers.get('content-type') ?? ''
  if (!type.includes('json')) return '-'
  try {
    const body = (await response.json()) as { reason?: string; error?: string; viewer?: string }
    return body.reason ?? body.error ?? body.viewer ?? '-'
  } catch {
    return '-'
  }
}

if (process.argv.includes('--serve')) {
  const origins = { public: PUBLIC, admin: ADMIN, partner: PARTNER }

  // Two hostnames, which on the free path is the whole of R16 and R24 in miniature.
  await startLocalEdge({ port: 8080, label: 'canonical', secret: EDGE_SECRET, origins })
  await startLocalEdge({
    port: 8081,
    label: 'protected',
    secret: EDGE_SECRET,
    origins,
    mintToken: async () => staffToken,
  })

  console.log('  Open in a browser:')
  console.log()
  console.log('    http://127.0.0.1:8080/          booking page — public, works')
  console.log('    http://127.0.0.1:8080/admin     staff console — 403, no token injected')
  console.log('    http://127.0.0.1:8081/admin     staff console — 200, renders the identity')
  console.log()
  console.log('  :8080 stands for the canonical <project>.pages.dev, which the Pages Access')
  console.log('  toggle does NOT protect. :8081 stands for the preview alias, which it does.')
  console.log('  Same origin, same code, same request — the only difference is whether a')
  console.log('  token came with it. That is R16 and R24 side by side.')
  console.log()
  console.log('  The origins on :3000-:3002 refuse anything that skips both edges (R24):')
  console.log()
  console.log('    curl -s -o /dev/null -w \'%{http_code}\\n\' http://127.0.0.1:3001/   # 403')
  console.log()
  console.log('  Tokens, if you want to drive the origin by hand — note it also requires the')
  console.log('  edge signature, so these alone will not get you in:')
  console.log()
  console.log(`    export STAFF_JWT=${staffToken}`)
  console.log(`    export PARTNER_JWT=${partnerToken}`)
  console.log(`    export FORGED_JWT=${forgedToken}`)
  console.log()
} else {
  jwksServer.close()
  process.exit(failed === 0 ? 0 : 1)
}
