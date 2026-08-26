# The Meridian Build — writeup

Repo: `github.com/DushyantRajpurohit/meridian-build` · Live: `meridian-clinic.pages.dev`
Full threat model in `docs/43-threat-model.md`, full runbooks in `docs/42-incident-runbooks.md`.

## The decision everything else follows from

Cloudflare Access is a filter. It is not the enforcement point.

That is forced, not stylistic. A Pages project answers on its canonical `pages.dev` hostname
whether or not I bind an Access application to anything (R16), so a public URL reaches my code
with no Access in front of it, permanently, and no policy removes it. That is the ordinary
condition of any reachable origin — the tunnel URL is the same problem in a different costume.

So the origin verifies the Access JWT itself, on every request, on every hostname: fetch the
team JWKS, check `kid`, verify RS256, pin `aud` to that one application, check `iss`, `exp`,
`nbf`, then decide whether the principal kind is allowed on that route. About forty lines with
`jose` primitives and no all-in-one verifier (GR6). Eight distinct refusal reasons, each
returned as a code rather than a generic 403, because a runbook that cannot tell `wrong_audience`
from `unknown_key` sends you to the wrong layer.

The three deciding tests pass at the unprotected canonical hostname, which is the only place
passing them means anything: no token → `403 no_token`; partner token at the staff console →
`403 wrong_audience`; forged signature with a real `kid` → `403 bad_signature`.

Behind that, a second gate: the Pages Function signs each request onto the tunnel with an
HMAC-SHA256 over the raw body plus a nonce and timestamp, and the origin refuses anything
arriving at the tunnel URL directly (`403 edge_nonce_missing`). Two independent failures are
required to reach the application unauthenticated.

## Threat model, condensed

**Assets:** patient booking data; lab results in flight (integrity matters more than
confidentiality — a forged result changes treatment); the staff console; three bearer
credentials (partner service token, Cloudflare API token, `EDGE_HMAC_SECRET`).

**Actors:** the untargeted scanner; someone who found the canonical hostname; a former staff
member — the likeliest real incident, and the one most builds handle worst; a partner whose
token leaked; a network-position attacker; and me, holding the API token.

**What it stops.** Inbound network attack categorically — no public IP, behind CGNAT, nothing
bound off loopback, so the port is absent rather than filtered. Unauthenticated access at
*either* hostname. Header-forged identity: `Cf-Access-Authenticated-User-Email` and four
siblings are deleted on arrival before anything can read them. Cross-audience replay — a real,
correctly signed, unexpired token from the same team is still the wrong token. Reaching the
origin around the edge. Password attacks, by not having passwords.

**What it does not stop, which is the half that matters.** A stolen live session on an unlocked
workstation is full staff access for the remainder of the session; the mitigation is a session
length, not a control. With one-time PIN the inbox *is* the identity — no second factor, and
Access cannot distinguish a compromised mailbox from a legitimate one because there is no
difference to tell. The service token is a bearer credential with no proof of possession. An
authorised user exporting everything on their last morning is indistinguishable from one doing
their job. Anyone with the API token can rewrite the entire posture, and Terraform makes that
faster, not slower. Every check here answers "who is this?" and none answers "should this
request be allowed?" — a validly authenticated partner posting a hostile lab result is inside
every control in this build. And if the box is compromised, Zero Trust protected the path to the
origin, not the origin.

One more, observed rather than theorised: KV rate-limit counters are eventually consistent. I
wrote that down before testing, then watched request 8 get through after 6 and 7 were correctly
429'd. The limiter raises the cost of abuse; it is not a ceiling.

## Incident timings

| # | Procedure | Measured |
|---|---|---|
| 4 | Staff console down — five-step triage | **diagnose 3s, recover 14s, total 17s** |
| 1 | Staff leaver — revoke *and* terminate the live session | blocked on `terraform apply` |
| 2 | Service token in a public paste — rotate under 60s | blocked on `terraform apply` |
| 3 | Tunnel token leaks | n/a — a quick tunnel has no token |

Drill 4 ran against the live system with the origin killed deliberately. Step 1 (edge) showed
`colo=BOM`, so the edge was fine; step 2 showed the connectors alive; step 3 found no listener on
3000–3002. Steps 4 and 5 were never reached — the runbook working, because the fault was
infrastructure and the ordering meant I never opened a policy page.

**The number is small because the fault was.** I killed a process on a box I was already logged
into. What the drill establishes is the ordering, not the duration. A real page at 03:00 is
bounded by access and by knowing where to look.

One thing I only learned by doing it: during the outage the user saw *Cloudflare's* 502 page,
not my Function's JSON error. A dead origin behind a live tunnel and a missing origin URL are
different failures that look identical, and the tell is whether the body is JSON.

Procedures 1 and 2 are written and ordered — 2's whole trick is create/distribute/revoke, so the
sixty-second clock covers only the final revoke — but they are not timed, because they need an
apply I could not run. Untimed is untimed; I am not claiming a number I did not measure.

## What I got wrong, and what it cost

**The one that reached production.** The booking form returned `{"error":"turnstile_missing"}`
for roughly twenty minutes and **the user found it, not me.** `.env.example` had no Turnstile
entry, so when I wrote `.env` I invented a name — `TURNSTILE_SITEKEY` — while the code read
`TURNSTILE_SITE_KEY`. A `?? ''` default meant the page rendered fine with an empty sitekey and
failed only at submission. Two lessons, both mine: a fallback on a *required* value converts a
startup failure into a runtime one, and an incomplete `.env.example` is not documentation debt,
it is a bug waiting for someone to guess. The sitekey is now required config that refuses to
start without it.

**`error code: 1101` on every request, immediately after the first deploy.** Tailing the
deployment showed `DataError: Imported HMAC key length (0)`. Pages binds secrets at *deploy*
time; I had set `EDGE_HMAC_SECRET` after deploying, so the running code held an empty key.
Redeploying fixed it. Cost: most of the first live hour, and far more without the tail — the
symptom names no layer at all.

**The repo did not install for anyone but me.** `pnpm-workspace.yaml`, `tsconfig.base.json` and
the linter config lived in the parent directory. `ERR_PNPM_CATALOG_ENTRY_NOT_FOUND_FOR_SPEC` on
a clean clone. I only found it because I actually cloned to a scratch path and ran install
rather than assuming. A public repo a reviewer can follow end to end is a deliverable, and mine
was broken for every reader.

**Two Terraform drifts, found by re-planning after the first apply** — which is the habit, not
the finding. Cloudflare returns the Turnstile `domains` list sorted; Terraform compares lists
positionally; the result was a permanent diff on a resource nobody had touched. `sort()` fixed
it. And the partner application had silently inherited the provider's default session duration,
so R15's "deliberate choice" was really "whatever the provider picked". Both were cosmetic in
effect and not in kind: a plan that is never clean is a plan people stop reading, and R40's
destroy-and-rebuild claim is only believable if the steady state is genuinely zero changes.

**An overclaim I had to retract.** I described R28 — a service principal refused on a human
route — as demonstrable in production. It is not. Access refuses the service token at the edge
with a 302, so the origin's check never fires. It is proven in the test suite, where the harness
mints a token for the console's own audience so `aud` cannot be what refuses it. The check is
real; my account of where you can watch it happen was wrong.

**Of the seven traps the assignment lists, none bit me** — R14's ordering, R21's header, R22's
`aud` and R29's per-IP counter were all designed for from the start. The things that actually
cost me time were operational: environment variable names, deploy-time secret binding, and a
repo that only worked on the machine that wrote it. That is roughly where I would expect real
incidents to come from too.

## Not done, and why

§7 (SSH and WARP through Access, 7 points) and the firewall half of R6 need root on this box,
which I do not have. R40's destroy-and-rebuild and R42's first two drills need
`terraform apply`, which only the user can run here. R8's connector is script-supervised rather
than a systemd unit, so it does not survive a reboot. Each is named where it is missing rather
than described as if it were done.
