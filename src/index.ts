import express, { type Express } from 'express'
import { createAdminApp } from './apps/admin'
import { createPartnerApp } from './apps/partner'
import { createPublicApp } from './apps/public'
import { loadConfig, ORIGIN_HEADER } from './config'

/**
 * Three plain Node processes' worth of surfaces in one process, bound to loopback only.
 *
 * GR1/R6 — nothing here binds to a routable interface. cloudflared makes the outbound
 * connection; there is no inbound path to open.
 */
const config = loadConfig()

const surfaces = [
  { name: 'public', port: config.ports.public, app: createPublicApp(config, { turnstileSiteKey: config.turnstileSiteKey }) },
  { name: 'admin', port: config.ports.admin, app: createAdminApp(config) },
  { name: 'partner', port: config.ports.partner, app: createPartnerApp(config) },
]

/**
 * Every response this box produces says which surface produced it, and that is load-bearing
 * rather than decorative.
 *
 * A quick tunnel's hostname is a lease. When Cloudflare reaps one, the name stops routing
 * here and Cloudflare answers it directly with a zero-length 404 carrying no content-type —
 * not the 530 the reap used to produce. Both the supervisor's health probe and the Pages
 * Function were reading "got an HTTP status back" as "the tunnel is alive", so a dead
 * hostname sat in KV looking healthy and the canonical hostname served 404 for hours.
 *
 * Sniffing for a missing content-type would work today and rot the moment Cloudflare changes
 * its error page. A header only this process can set answers the actual question — *did my
 * origin produce this response* — and cannot be produced by an edge answering on behalf of a
 * name it no longer routes.
 */
function identified(name: string, app: Express): Express {
  const wrapper = express()
  wrapper.use((_req, res, next) => {
    res.setHeader(ORIGIN_HEADER, name)
    next()
  })
  wrapper.use(app)
  return wrapper
}

for (const surface of surfaces) {
  identified(surface.name, surface.app).listen(surface.port, config.bindHost, () => {
    console.log(`[${surface.name.padEnd(7)}] http://${config.bindHost}:${surface.port}`)
  })
}

console.log(`issuer ${config.issuer}`)
console.log(`admin aud   ${mask(config.audiences.admin)}`)
console.log(`partner aud ${mask(config.audiences.partner)}`)

function mask(value: string): string {
  return value.length <= 8 ? '********' : `${value.slice(0, 6)}…${value.slice(-4)}`
}
