import { generateKeyPair, SignJWT } from 'jose'

/**
 * R23 — mints $FORGED_JWT for the acceptance suite: a syntactically perfect Access token,
 * signed by a key pair generated here and published nowhere.
 *
 * It carries a real kid from the team JWKS, so the origin does not get to dismiss it cheaply
 * on a lookup miss — it has to fetch the right key and find that the signature fails against
 * it. That is the check being demonstrated.
 *
 *   pnpm forge --team meridian.cloudflareaccess.com --aud $ACCESS_AUD_ADMIN --kid <kid>
 */

const args = parseArgs(process.argv.slice(2))
const team = args.team ?? process.env.CF_TEAM_DOMAIN
const aud = args.aud ?? process.env.ACCESS_AUD_ADMIN
const email = args.email ?? 'ceo@meridian.test'

if (team === undefined || aud === undefined) {
  console.error('usage: pnpm forge --team <team>.cloudflareaccess.com --aud <AUD tag> [--kid <kid>] [--email <address>]')
  process.exit(2)
}

const issuer = `https://${team}`
const kid = args.kid ?? (await firstPublishedKid(issuer))

const { privateKey } = await generateKeyPair('RS256', { extractable: true })
const now = Math.floor(Date.now() / 1000)

const token = await new SignJWT({ email, sub: 'sub-forged', identity_nonce: 'forged', type: 'app' })
  .setProtectedHeader({ alg: 'RS256', kid })
  .setIssuer(issuer)
  .setAudience(aud)
  .setIssuedAt(now)
  .setExpirationTime(now + 3600)
  .sign(privateKey)

console.error(`forged token: iss=${issuer} aud=${aud.slice(0, 8)}… kid=${kid} email=${email}`)
console.error('signed by a key that exists only in this process. Expect 403 bad_signature.')
console.log(token)

async function firstPublishedKid(iss: string): Promise<string> {
  const response = await fetch(`${iss}/cdn-cgi/access/certs`)
  if (!response.ok) throw new Error(`${iss}/cdn-cgi/access/certs returned ${response.status}`)
  const body = (await response.json()) as { keys?: { kid?: string }[] }
  const found = body.keys?.[0]?.kid
  if (typeof found !== 'string') throw new Error('team published no kid to borrow')
  return found
}

function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]
    const value = argv[i + 1]
    if (key?.startsWith('--') === true && value !== undefined) out[key.slice(2)] = value
  }
  return out
}
