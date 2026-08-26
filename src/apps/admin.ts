import express, { type Express } from 'express'
import { requireAccess, requireUser } from '../access/middleware'
import { requireEdgeSignature } from '../access/edge'
import type { MeridianConfig } from '../config'
import { appointments } from '../store'

/**
 * :3001 — the staff console. Access gates the hostname; this gates the application.
 *
 * The two are not the same claim, and the difference is the whole assignment: Access can only
 * speak for requests that went through Access. This process answers on 127.0.0.1 and cannot
 * tell by looking at a socket whether the request came through the edge, through the quick
 * tunnel that is public by design on the free path, or from something else on the box.
 */
export function createAdminApp(config: MeridianConfig): Express {
  const app = express()
  app.disable('x-powered-by')
  app.use(express.raw({ type: '*/*', limit: '64kb' }))

  // Proof the request came through the edge rather than straight to the quick tunnel. It
  // runs first and decides nothing about identity; the token check below still has to pass.
  if (config.requireEdgeSignature) {
    app.use(requireEdgeSignature({ secret: config.edgeHmacSecret }))
  }

  // R20 — mounted at the root, before any route, so there is no ordering mistake that leaves
  // a handler exposed. Nothing on this app is reachable without a verified token.
  app.use(
    requireAccess({
      jwks: config.jwks,
      issuer: config.issuer,
      audience: config.audiences.admin,
      onDecision: (event) => {
        const who = event.principal?.kind === 'user' ? event.principal.email : (event.principal?.clientId ?? '-')
        console.log(`[admin] ${event.allowed ? 'allow' : 'deny '} ${event.reason} ${event.method} ${event.path} ${who}`)
      },
    }),
  )

  // R27/R28 — past the token check, still not past the question of who. A service token is a
  // genuine Access principal and is refused here rather than being handed a staff session.
  app.use(requireUser(config.staffEmails))

  // R21 — the page renders req.principal, which came from verified claims. It never reads
  // Cf-Access-Authenticated-User-Email; that header was deleted on the way in.
  app.get('/', (req, res) => {
    const principal = req.principal
    const email = principal?.kind === 'user' ? principal.email : 'unknown'
    res.type('html').send(`<!doctype html>
<meta charset="utf-8">
<title>Meridian staff console</title>
<style>body{font:16px/1.6 system-ui;margin:3rem auto;max-width:44rem;color:#111}code{background:#f4f4f5;padding:.1rem .3rem;border-radius:3px}</style>
<h1>Meridian staff console</h1>
<p>Signed in as <strong>${escapeHtml(email)}</strong>.</p>
<p>Identity came from the <code>aud</code>-pinned Access token on this request, not from a header.</p>
<pre>${escapeHtml(JSON.stringify(principal, null, 2))}</pre>
<p><a href="/api/patients">/api/patients</a></p>`)
  })

  app.get('/api/patients', (req, res) => {
    const principal = req.principal
    res.json({
      viewer: principal?.kind === 'user' ? principal.email : null,
      appointments,
    })
  })

  return app
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)
}
