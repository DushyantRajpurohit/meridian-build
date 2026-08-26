import express, { type Express } from 'express'
import { requireAccess, requireService } from '../access/middleware'
import { requireEdgeSignature } from '../access/edge'
import { jsonBody } from '../body'
import type { MeridianConfig } from '../config'
import { labResults } from '../store'

/**
 * :3002 — the partner lab's server. No human, no browser, no SSO. R25/R26: the caller
 * presents CF-Access-Client-Id and CF-Access-Client-Secret at the edge, Access exchanges them
 * for a signed assertion, and this origin sees the same kind of token the staff console sees
 * — with a different aud and no email on it.
 */
export function createPartnerApp(config: MeridianConfig): Express {
  const app = express()
  app.disable('x-powered-by')

  // Raw bytes, because the edge signature below is over exactly what arrived.
  app.use(express.raw({ type: '*/*', limit: '64kb' }))

  if (config.requireEdgeSignature) {
    app.use(requireEdgeSignature({ secret: config.edgeHmacSecret }))
  }

  app.use(
    requireAccess({
      jwks: config.jwks,
      issuer: config.issuer,
      // R22 — the partner's aud. A staff token presented here fails this check even though
      // it is signed by the same key, by the same issuer, for the same team.
      audience: config.audiences.partner,
    }),
  )

  // R27 — the mirror of the admin guard. A human's token would be refused here.
  app.use(requireService(config.partnerClientIds.length > 0 ? config.partnerClientIds : undefined))

  app.get('/v1/results', (_req, res) => {
    res.json({ results: labResults })
  })

  app.post('/v1/results', (req, res) => {
    const body = jsonBody(req) as Partial<{ patient: string; panel: string; value: string }> | undefined
    if (
      body === undefined ||
      typeof body.patient !== 'string' ||
      typeof body.panel !== 'string' ||
      typeof body.value !== 'string'
    ) {
      res.status(400).json({ error: 'patient, panel and value are required' })
      return
    }
    const result = {
      id: `lr-${(labResults.length + 1).toString().padStart(3, '0')}`,
      patient: body.patient,
      panel: body.panel,
      value: body.value,
      receivedAt: new Date().toISOString(),
    }
    labResults.push(result)
    res.status(201).json(result)
  })

  return app
}
