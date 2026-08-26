import { createAdminApp } from './apps/admin'
import { createPartnerApp } from './apps/partner'
import { createPublicApp } from './apps/public'
import { loadConfig } from './config'

/**
 * Three plain Node processes' worth of surfaces in one process, bound to loopback only.
 *
 * GR1/R6 — nothing here binds to a routable interface. cloudflared makes the outbound
 * connection; there is no inbound path to open.
 */
const config = loadConfig()

const surfaces = [
  { name: 'public ', port: config.ports.public, app: createPublicApp(config, { turnstileSiteKey: config.turnstileSiteKey }) },
  { name: 'admin  ', port: config.ports.admin, app: createAdminApp(config) },
  { name: 'partner', port: config.ports.partner, app: createPartnerApp(config) },
]

for (const surface of surfaces) {
  surface.app.listen(surface.port, config.bindHost, () => {
    console.log(`[${surface.name}] http://${config.bindHost}:${surface.port}`)
  })
}

console.log(`issuer ${config.issuer}`)
console.log(`admin aud   ${mask(config.audiences.admin)}`)
console.log(`partner aud ${mask(config.audiences.partner)}`)

function mask(value: string): string {
  return value.length <= 8 ? '********' : `${value.slice(0, 6)}…${value.slice(-4)}`
}
