import { JwksCache } from './access/jwks'

/**
 * Every value here comes from the environment. Nothing in this repository holds a secret at
 * any commit (GR2) — .env is gitignored and .env.example carries the shape only.
 */
export interface MeridianConfig {
  /** e.g. meridian.cloudflareaccess.com */
  teamDomain: string
  issuer: string
  jwks: JwksCache
  /** R19 — one AUD tag per Access application. They are not interchangeable; see R22. */
  audiences: { admin: string; partner: string }
  staffEmails: readonly string[]
  partnerClientIds: readonly string[]
  /** Shared with the Pages Function, which signs the hop to a public quick tunnel. */
  edgeHmacSecret: string
  /**
   * Whether an unsigned request is refused outright. True on the free path, where the origin
   * is reachable at a public URL. Never a substitute for the token check — see access/edge.ts.
   */
  requireEdgeSignature: boolean
  /** R32 — the partner lab's webhook signing key. */
  labWebhookSecret: string
  /** R31 — verified server-side on every booking. */
  turnstileSecret: string
  /**
   * R31 — public by design; it is embedded in the booking page so the widget can render.
   *
   * Required rather than optional-with-a-default. An empty sitekey renders a widget that
   * silently produces no token, so every booking is then refused with `turnstile_missing` —
   * a runtime mystery on a page that looks fine. Failing at startup turns a misconfiguration
   * into a message that names the variable.
   */
  turnstileSiteKey: string
  bindHost: string
  ports: { public: number; admin: number; partner: number }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): MeridianConfig {
  const teamDomain = required(env, 'CF_TEAM_DOMAIN')
  const issuer = `https://${teamDomain}`

  return {
    teamDomain,
    issuer,
    jwks: new JwksCache({ certsUrl: `${issuer}/cdn-cgi/access/certs` }),
    audiences: {
      admin: required(env, 'ACCESS_AUD_ADMIN'),
      partner: required(env, 'ACCESS_AUD_PARTNER'),
    },
    staffEmails: list(env.STAFF_EMAILS),
    partnerClientIds: list(env.PARTNER_CLIENT_IDS),
    edgeHmacSecret: required(env, 'EDGE_HMAC_SECRET'),
    requireEdgeSignature: env.REQUIRE_EDGE_SIGNATURE !== 'false',
    labWebhookSecret: required(env, 'LAB_WEBHOOK_SECRET'),
    turnstileSecret: required(env, 'TURNSTILE_SECRET'),
    turnstileSiteKey: required(env, 'TURNSTILE_SITE_KEY'),
    // R7 trap — bind the literal IPv4 loopback. `localhost` may resolve to ::1 first, and a
    // tunnel pointed at 127.0.0.1 then sees an intermittent connection refused that reads as
    // a Cloudflare fault.
    bindHost: env.BIND_HOST ?? '127.0.0.1',
    ports: {
      public: port(env.PORT_PUBLIC, 3000),
      admin: port(env.PORT_ADMIN, 3001),
      partner: port(env.PORT_PARTNER, 3002),
    },
  }
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is not set — copy .env.example to .env and fill it in`)
  }
  return value
}

function list(value: string | undefined): readonly string[] {
  if (value === undefined) return []
  return value
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0)
}

function port(value: string | undefined, fallback: number): number {
  const parsed = value === undefined ? Number.NaN : Number.parseInt(value, 10)
  return Number.isInteger(parsed) ? parsed : fallback
}

/**
 * The header every surface stamps on every response, naming itself.
 *
 * The Pages Function requires it before accepting a response as the origin's (see
 * pages/functions/_lib/origin.ts, which declares the same name), and the tunnel supervisor
 * requires it before calling a published hostname healthy. Both halves are written
 * separately and pinned together by test/edge.test.ts, the same way the edge signature is.
 */
export const ORIGIN_HEADER = 'x-meridian-origin'
