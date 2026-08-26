# R43 — Threat model

One page. The last section is the one that matters.

## Assets

| Asset | Where it lives | Why someone wants it |
|---|---|---|
| Patient booking data (name, contact, reason for visit) | origin process, in memory / store | health data; identifying, sellable, and embarrassing to leak |
| Lab results moving partner → clinic | `POST /v1/results`, `/hooks/lab` | same, plus integrity: a forged result changes treatment |
| Staff console access | `staff.<project>.pages.dev` | it is the read/write view over everything above |
| The partner service token | Cloudflare, `.env`, Terraform state | a bearer credential with no human behind it and a one-year life |
| The Cloudflare API token | `.env` (0600, gitignored) | it can rewrite the entire security posture, including deleting it |
| The tunnel token | `cloudflared` config on the box | it is the box's identity as an origin |
| `EDGE_HMAC_SECRET` | `.env` and the Pages Function | forging it lets a request claim it came through the edge |

## Actors

1. **Opportunistic internet scanner.** Untargeted, automated, high volume. Wants any open port
   or unauthenticated endpoint.
2. **Someone who found the canonical `pages.dev` hostname.** Not sophisticated — the URL is
   discoverable — but they are past the Access edge by construction (R16).
3. **A former staff member.** Knows the hostnames, the workflow, and possibly still has a live
   browser session. This is the most likely real incident and the one most builds handle worst.
4. **A compromised or careless partner.** The lab's token leaks into a paste, a log, a repo.
   The token itself is behaving exactly as designed; the holder has changed.
5. **A network-position attacker** between a clinic device and Cloudflare — coffee shop, hotel,
   hostile ISP.
6. **Me, with the API token.** The insider case, and the one with the largest blast radius.

## What this architecture stops

- **Inbound network attack, categorically.** No public IP, no port forward, nothing bound off
  loopback. There is no socket for an actor of type 1 to find. This is not a filtered port; it
  is an absent one, and the distinction survives misconfiguration.
- **Reaching the app without identity, at either hostname.** Access blocks at the edge on the
  bound hostname; on the unbound canonical hostname the request arrives and the **origin**
  refuses it (`403 no_token`). Actor 2 gets nothing, and this is the single most important
  property in the build: the edge is a filter, not the enforcement point.
- **Header-forged identity.** `Cf-Access-Authenticated-User-Email` and four siblings are
  deleted on arrival before anything reads them. Identity comes from a signature or not at all.
- **Cross-audience token replay.** A valid partner token presented to the staff console is
  refused on `aud`, and a service principal on a human route is refused on principal kind. A
  real, correctly-signed, unexpired token from the same team is still the wrong token.
- **Reaching the origin around the edge.** The tunnel URL is public; a request arriving there
  without the edge's HMAC is refused (`403 edge_nonce_missing`).
- **Credential-stuffing and password attacks.** There are no passwords, no sessions of ours, and
  no user table (GR3). The attack surface does not exist rather than being defended.
- **Automated abuse of the public form.** Turnstile plus device and network rate limits in KV.
- **Passive interception (actor 5).** Everything is Cloudflare-terminated HTTPS, and the origin
  hop never leaves the box.

## What it does **not** stop

This is the honest half.

- **A stolen live session.** An 8-hour session on an unlocked, unattended clinic workstation is
  full staff access. Nothing here does device posture or continuous re-authentication. This is
  the residual risk I consciously accepted in R15, and the mitigation is a session length, not
  a control.
- **Compromise of a staff member's email.** With one-time PIN, the inbox *is* the identity.
  There is no second factor. Anyone reading a staff member's email can be that staff member,
  and Access cannot tell the difference because there is no difference to tell. This is the
  cost of R12's convenience and it is the largest single weakness in the design.
- **The service token, in the hands of whoever holds it.** It is a bearer credential. It carries
  no proof of possession, no origin binding, no user. A leaked token is full partner API access
  until someone rotates it — which is precisely why R42 rehearses that rotation under a clock.
- **An authorised user doing authorised things maliciously.** Current staff can read every
  record they are entitled to read. There is no rate limiting on authenticated staff reads, no
  anomaly detection, no per-record access log. A departing employee who exports everything on
  their last morning is indistinguishable from one doing their job.
- **Me, or anyone with the Cloudflare API token.** That token can delete the applications,
  rewrite the policies, and issue new service tokens. There is no second approver, no
  protected-branch equivalent for the account, and Terraform makes the destruction *faster*,
  not slower. Access audit logs would record it after the fact.
- **Malicious content in an otherwise valid request.** Every enforcement check here answers
  "who is this?" and none answers "should this particular request be allowed?" A validly
  authenticated partner posting a malformed or hostile lab result is inside every control in
  this document.
- **The origin box itself.** If this machine is compromised, the attacker inherits the tunnel,
  the secrets in `.env`, and the running process. Zero Trust protects the path to the origin,
  not the origin.
- **KV's consistency window.** Rate-limit counters are eventually consistent across
  datacentres. A distributed burst arriving simultaneously in several colos can exceed the
  nominal limit before the counters converge. The limiter raises the cost of abuse; it does not
  impose a hard ceiling, and claiming otherwise would be the kind of thing this section exists
  to prevent.
- **Availability.** Everything here is Cloudflare-dependent. If Cloudflare is down, or the
  account is suspended, the clinic has no console and no partner API. There is no break-glass
  path, deliberately — a break-glass path is an unauthenticated path, and it would be the first
  thing an attacker looked for.
- **The Pages preview-alias binding itself.** Access is bound to a hostname pattern. If a future
  preview deployment produces a hostname the pattern does not cover, that hostname is
  unprotected the same way the canonical one is. The origin still refuses it — which is the
  entire argument for enforcing at the origin — but the edge protection is a configuration that
  can silently stop matching, not an invariant.
