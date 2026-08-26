import { createFakeTeam } from '../test/harness'
import { AccessDenied, verifyAccessToken } from '../src/access/verify'

/**
 * R22 — "Show it being accepted by a middleware that skips aud, then show it rejected once
 * aud is pinned. Include both outputs."
 *
 * This is that demonstration, run against a local team so it is reproducible by a reviewer
 * with no access to ours. The same sequence against the live team is in the recording.
 *
 *   pnpm tsx scripts/cross-audience.ts
 */

const team = await createFakeTeam()
const { issuer, jwks, audiences } = team.config

// A token Access minted for the partner API. Genuine in every respect.
const partnerToken = await team.mintService()

console.log('token minted for : partner API')
console.log('presented to     : staff console')
console.log(`issuer           : ${issuer}`)
console.log(`partner aud      : ${audiences.partner.slice(0, 12)}…`)
console.log(`admin aud        : ${audiences.admin.slice(0, 12)}…`)
console.log()

console.log('--- middleware WITHOUT the aud check -------------------------------')
try {
  const principal = await verifyAccessToken(partnerToken, { jwks, issuer, audience: null })
  console.log('ACCEPTED. Signature valid, issuer valid, not expired.')
  console.log(`principal: ${JSON.stringify(principal)}`)
  console.log('The staff console would now be open to the partner lab’s service token,')
  console.log('and to a token from every other application in the team.')
} catch (error) {
  console.log(`unexpectedly rejected: ${describe(error)}`)
}

console.log()
console.log('--- middleware WITH aud pinned to the staff console ----------------')
try {
  await verifyAccessToken(partnerToken, { jwks, issuer, audience: audiences.admin })
  console.log('ACCEPTED — this is a bug; the demonstration has stopped working.')
  process.exitCode = 1
} catch (error) {
  console.log(`REJECTED. ${describe(error)}`)
  console.log('Same token, same signature, same issuer. One claim decides it.')
}

function describe(error: unknown): string {
  return error instanceof AccessDenied ? `${error.code}: ${error.message}` : String(error)
}
