import express, { type Express } from 'express'
import { requireEdgeSignature } from '../access/edge'
import { formBody, rawBody } from '../body'
import type { MeridianConfig } from '../config'
import { checkSignature, ReplayCache } from '../hmac'
import { addAppointment } from '../store'

/**
 * :3000 — the one surface deliberately open to the world. No Access application in front of
 * it, which is exactly why it needs the rest: a verified Turnstile token on the booking form
 * (R31) and a signed body on the lab webhook (R32).
 *
 * The edge signature matters most here, of all three surfaces. Everything protecting this
 * endpoint from volume — the rate limiter and the filtering rule — lives in the Pages
 * Function, and the origin is on a public URL. Without the signature check, /book is
 * reachable directly and both of them are decoration.
 */
export interface PublicAppOptions {
  turnstileSiteKey?: string
  /** Injected in tests; the real one calls Cloudflare. */
  verifyTurnstile?: TurnstileVerifier
}

export type TurnstileVerifier = (token: string, remoteIp?: string) => Promise<boolean>

export function createPublicApp(config: MeridianConfig, options: PublicAppOptions = {}): Express {
  const app = express()
  app.disable('x-powered-by')
  app.use(express.raw({ type: '*/*', limit: '256kb' }))

  if (config.requireEdgeSignature) {
    app.use(requireEdgeSignature({ secret: config.edgeHmacSecret }))
  }

  const verifyTurnstile = options.verifyTurnstile ?? makeTurnstileVerifier(config.turnstileSecret)
  const replayCache = new ReplayCache()

  app.get('/', (_req, res) => {
    res.type('html').send(bookingPage(options.turnstileSiteKey ?? config.turnstileSiteKey))
  })

  // R31 — the token is verified server-side before anything is written. A Turnstile widget
  // whose token is never checked is decoration: the widget runs in the client, and a client
  // that means harm simply does not run it.
  app.post('/book', (req, res) => {
    void (async () => {
      const form = formBody(req)
      const token = form.get('cf-turnstile-response')

      if (token === null || token.length === 0) {
        res.status(400).json({ error: 'turnstile_missing' })
        return
      }
      if (!(await verifyTurnstile(token, req.ip))) {
        res.status(400).json({ error: 'turnstile_failed' })
        return
      }

      const name = (form.get('name') ?? '').trim()
      const reason = (form.get('reason') ?? '').trim()
      if (name.length === 0) {
        res.status(400).json({ error: 'name_required' })
        return
      }

      res.status(201).json(addAppointment(name.slice(0, 80), reason.slice(0, 200)))
    })()
  })

  // R32 — the lab's appliance cannot do SSO or service tokens, so it signs instead. This is
  // the lab's own signature over its own body, separate from and inside the edge signature:
  // the Function proves the route, this proves the sender.
  app.post('/hooks/lab', (req, res) => {
    const failure = checkSignature({
      secret: config.labWebhookSecret,
      rawBody: rawBody(req),
      signature: header(req.headers['x-signature']),
      timestamp: header(req.headers['x-timestamp']),
      replayCache,
    })

    if (failure !== null) {
      console.log(`[public] webhook rejected: ${failure}`)
      res.status(401).json({ error: 'unauthorized', reason: failure })
      return
    }

    res.status(202).json({ accepted: true })
  })

  return app
}

function header(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value
}

function makeTurnstileVerifier(secret: string): TurnstileVerifier {
  return async (token, remoteIp) => {
    const form = new URLSearchParams({ secret, response: token })
    if (remoteIp !== undefined) form.set('remoteip', remoteIp)

    try {
      const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        body: form,
        signal: AbortSignal.timeout(5_000),
      })
      const outcome = (await response.json()) as { success?: boolean }
      return outcome.success === true
    } catch {
      // Fail closed. A booking form that accepts everything whenever Cloudflare is slow is
      // the same hole as never verifying, just harder to notice.
      return false
    }
  }
}

function bookingPage(siteKey: string): string {
  return `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Book an appointment · Meridian Clinic</title>
<style>body{font:16px/1.6 system-ui;margin:3rem auto;max-width:32rem;color:#111;padding:0 1rem}
label{display:block;margin:1rem 0 .25rem;font-weight:600}input,textarea{width:100%;padding:.5rem;font:inherit;border:1px solid #ccc;border-radius:4px}
button{margin-top:1rem;padding:.6rem 1.2rem;font:inherit;background:#0b6;color:#fff;border:0;border-radius:4px;cursor:pointer}</style>
<h1>Meridian Clinic</h1>
<p>Book an appointment. No account needed.</p>
<form method="post" action="/book">
  <label for="name">Your name</label>
  <input id="name" name="name" required maxlength="80">
  <label for="reason">Reason for visit</label>
  <textarea id="reason" name="reason" rows="3" maxlength="200"></textarea>
  <div class="cf-turnstile" data-sitekey="${siteKey}"></div>
  <button type="submit">Request appointment</button>
</form>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`
}
