# The Meridian Build — writeup

Long forms in `docs/`.

## The decision everything else follows from

Cloudflare Access is a filter, not the enforcement point.

That is forced, not stylistic. A Pages project answers on its canonical `pages.dev` hostname
whether or not I bind an Access application to anything (R16), so a public URL reaches my code
with no Access in front of it, permanently — the ordinary condition of any reachable origin, and
the tunnel URL is the same problem in a different costume.

So the origin verifies the Access JWT itself, on every request, on every hostname: fetch the
team JWKS, check `kid`, verify RS256, pin `aud` to that one application, check `iss`, `exp` and
`nbf`, then decide whether the principal kind is allowed on that route. Forty lines of `jose`
primitives, no all-in-one verifier (GR6). Eight refusal reasons, each returned as a code:
a runbook that cannot tell `wrong_audience` from `unknown_key` sends you to the wrong layer.

The three deciding tests pass at the *unprotected* canonical hostname, the only place passing
them means anything: no token → `403 no_token`; partner token at the staff console →
`403 wrong_audience`; forged signature with a real `kid` → `403 bad_signature`.

A second gate sits behind it: the Function signs each request onto the tunnel with HMAC-SHA256
over the raw body plus a nonce and timestamp, and the origin refuses anything unsigned at the
tunnel URL (`403 edge_nonce_missing`). Reaching the application unauthenticated takes two
independent failures.

## Threat model, condensed

**Assets:** patient booking data; lab results in flight (integrity over confidentiality — a
forged result changes treatment); the staff console; three bearer credentials (partner service
token, Cloudflare API token, `EDGE_HMAC_SECRET`).

**Actors:** the untargeted scanner; someone who found the canonical hostname; a former staff
member — the likeliest real incident, and the one most builds handle worst; a partner whose
token leaked; and me, holding the API token.

**What it stops.** Inbound network attack categorically — no public IP, behind CGNAT, nothing
bound off loopback, so the port is absent rather than filtered. Unauthenticated access at
*either* hostname. Header-forged identity: `Cf-Access-Authenticated-User-Email` and four siblings
are deleted on arrival before anything reads them. Cross-audience replay — a real, correctly
signed, unexpired token from the same team is still the wrong token. Password attacks, by not
having passwords.

**What it does not stop, the half that matters.** A stolen live session on an unlocked
workstation is full staff access until it expires; the mitigation is a session length, not a
control. With one-time PIN the inbox *is* the identity — no second factor, and a compromised
mailbox is indistinguishable from a legitimate one. The service token is a bearer
credential with no proof of possession. An authorised user exporting everything on their last
morning looks like one doing their job. Anyone with the API token can rewrite the posture, and
Terraform makes that faster, not slower. Every check here answers "who is this?" and none
answers "should this request be allowed?" — a validly authenticated partner posting a hostile
lab result is inside every control here. And if the box is compromised, Zero Trust protected the
path to the origin, not the origin.

## Incident timings

- **Drill 1, staff leaver** — revoke *and* terminate the session: **67s.**
- **Drill 2, leaked service token** — rotate: **96s against a 60s target. Missed.**
- **Drill 4, staff console down** — five-step triage, steps 4 and 5 never reached because the
  ordering meant I never opened a policy page: **3s to diagnose, 14s to recover.** Small
  because the fault was; it establishes ordering, not duration.
- **Drill 5, unplanned** — the tunnels died on their own: **~90s to diagnose, 53s to recover.**
- **Drill 6, unplanned** — they died again, for a second reason: **90s to recover.**
- **Drill 3, tunnel token leaks** — n/a here.

Drills 5 and 6 were not drills. Both times the hostnames had been reaped at Cloudflare's end
while all three `cloudflared` processes still ran, and `curl` returning `000` rather than a
status was the tell: that is DNS failing. A live connector is not a live tunnel. Nothing crashed
either time — the system went dark on its own schedule, which is exactly why R8 asks for a
managed service.

**Drill 1 taught me a step missing from my own runbook.** The staff allowlist lives in two
places — Access, and the origin's `STAFF_EMAILS` — so editing only the Terraform side leaves the
origin willing to serve the leaver on the unbound canonical hostname, the exact path this build
defends. The lists had already drifted: Access allowed six, the origin one.

**Drill 2 missed its own target, and that is the more useful result.** Steps 1–3 cost zero
downtime exactly as the create/distribute/revoke ordering predicts — both credentials returned
200 simultaneously. Then Terraform planned the token delete *before* the policy update that
released it, Cloudflare refused with `400 code 12139`, and recovery took two targeted applies —
35 seconds I had never budgeted because I had never run it. Step 4 is two applies, not one. The
miss cost nothing real: the partner was already migrated, so 96 seconds revoked a credential
nobody legitimate was using. Reverse the ordering and they are 96 seconds of a lab unable to
deliver results.

## What I got wrong, and what it cost

**The one that reached production.** The booking form returned `{"error":"turnstile_missing"}`
for about twenty minutes and **the user found it, not me.** `.env.example` had no Turnstile
entry, so writing `.env` I invented a name — `TURNSTILE_SITEKEY` — while the code read
`TURNSTILE_SITE_KEY`. A `?? ''` default meant the page rendered fine with an empty sitekey and
failed only at submission: a fallback on a *required* value turns a startup failure into a
runtime one, and an incomplete `.env.example` is a bug waiting for someone to guess. The sitekey
is now required config.

**`error code: 1101` on every request after the first deploy.** Tailing the deployment showed
`DataError: Imported HMAC key length (0)`. Pages binds secrets at *deploy* time; I had set
`EDGE_HMAC_SECRET` afterwards, so the code held an empty key. Cost: most of the first live hour,
and far more without the tail — the symptom names no layer at all.

**The worst bug in the build, found by drill 5 and not by me.** The Function caches each
origin URL per isolate and drops it when the origin stops answering — except a dead quick tunnel
**does not throw** inside a Worker. Cloudflare answers the subrequest itself with 530, so
`fetch` resolves, the retry path never ran, and an isolate holding a stale URL served that 530
for its whole life. That is why the hostname alternated 200/530 by isolate. My retry was
correct and unreachable, which is the most expensive kind of wrong. The Function now treats 530
as unreachable, which is safe because the origin cannot produce one.

**The fix that caused the next outage.** Drill 5's repair added a guard: if *every* surface
fails in one probe round, assume the uplink dropped and do not rotate, because three independent
tunnels do not die in the same instant. They are not independent — quick-tunnel leases are issued
together and expire together, so I had written the true positive into an exemption, and the
supervisor sat through a second reap logging `local network fault` with nothing wrong with the
network. It now asks a control URL that is not mine before concluding anything. Drill 6 also
found **two** supervisors racing on the same KV keys, half the connectors serving a URL nothing
pointed at. There is a lock now.

**An overclaim I retracted.** I described R28 — a service principal refused on a human route —
as demonstrable in production. It is not: Access refuses the token at the edge with a 302, so the
origin's check never fires. It is proven in the tests, where the harness mints a token for the
console's own audience so `aud` cannot be what refuses it. The check is real; my account of where
you can watch it was wrong.

**Of the seven listed traps, none bit me** — R14's ordering, R21's header, R22's `aud` and
R29's per-IP counter were designed for from the start. What cost time was operational: a variable
name, deploy-time secret binding, a repo that only installed on the machine that wrote it
(`ERR_PNPM_CATALOG_ENTRY_NOT_FOUND_FOR_SPEC` on a clean clone), and two error paths that could
not be reached. Roughly where real incidents come from, too.

## Not done, and why

§7 (SSH and WARP through Access, 7 points) and the firewall half of R6 need root on this box.
R8's connector is script-supervised, not a systemd unit — drills 5 and 6 are what that costs.
R40 is done: 12 resources destroyed and rebuilt in 291s with no dashboard click, six
Cloudflare-issued identifiers changing underneath, which is the part that makes a rebuild hard.
Each gap is named where it is missing rather than described as done.
