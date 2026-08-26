# The Meridian Build — writeup

Long forms in `docs/`.

## The decision everything else follows from

Cloudflare Access is a filter, not the enforcement point.

That is forced, not stylistic. A Pages project answers on its canonical `pages.dev` hostname
whether or not I bind an Access application to anything (R16), so a public URL reaches my code
with no Access in front of it, permanently. That is the ordinary condition of any reachable
origin — the tunnel URL is the same problem in a different costume.

So the origin verifies the Access JWT itself, on every request, on every hostname: fetch the
team JWKS, check `kid`, verify RS256, pin `aud` to that one application, check `iss`, `exp` and
`nbf`, then decide whether the principal kind is allowed on that route. Forty lines of `jose`
primitives, no all-in-one verifier (GR6). Eight refusal reasons, each returned as a code, because
a runbook that cannot tell `wrong_audience` from `unknown_key` sends you to the wrong layer.

The three deciding tests pass at the *unprotected* canonical hostname, the only place passing
them means anything: no token → `403 no_token`; partner token at the staff console →
`403 wrong_audience`; forged signature with a real `kid` → `403 bad_signature`.

A second gate sits behind it: the Function signs each request onto the tunnel with HMAC-SHA256
over the raw body plus a nonce and timestamp, and the origin refuses anything arriving at the
tunnel URL unsigned (`403 edge_nonce_missing`). Reaching the application unauthenticated takes
two independent failures.

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

**What it does not stop, which is the half that matters.** A stolen live session on an unlocked
workstation is full staff access until it expires; the mitigation is a session length, not a
control. With one-time PIN the inbox *is* the identity — no second factor, and Access cannot
distinguish a compromised mailbox from a legitimate one. The service token is a bearer
credential with no proof of possession. An authorised user exporting everything on their last
morning looks like one doing their job. Anyone with the API token can rewrite the posture, and
Terraform makes that faster, not slower. Every check here answers "who is this?" and none
answers "should this request be allowed?" — a validly authenticated partner posting a hostile
lab result is inside every control here. And if the box is compromised, Zero Trust protected the
path to the origin, not the origin.

## Incident timings

- **Drill 1, staff leaver** — revoke *and* terminate the session: **67s.**
- **Drill 2, leaked service token** — rotate: **96s against a 60s target. Missed.**
- **Drill 4, staff console down** — five-step triage: **3s to diagnose, 14s to recover.**
- **Drill 5, unplanned** — the tunnels died on their own: **~90s to diagnose, 53s to recover.**
- **Drill 3, tunnel token leaks** — n/a on this path.

Drill 4 ran with the origin killed deliberately: the edge was fine, the connectors alive, no
listener on 3000–3002. Steps 4 and 5 were never reached — the runbook working, because the fault
was infrastructure and the ordering meant I never opened a policy page. The number is small
because the fault was; the drill establishes ordering, not duration.

Drill 5 was not a drill. Checking the URLs before submission, the public hostname returned 530
while the Access-bound two still gave 302 and 403 — they never reach the origin, so only the
public one could show it. The three `cloudflared` processes were **still running**: the quick
tunnel hostnames had been reaped at Cloudflare's end, and `curl` returning `000` rather than a
status was the tell, because that is DNS failing. A live connector process is not a live tunnel.
Nothing crashed — the system went dark on its own schedule while I was not looking, which is
exactly why R8 asks for a managed service.

**Drill 1 taught me a step missing from my own runbook.** The staff allowlist exists in two
places — Access, and the origin's `STAFF_EMAILS`. Editing only the Terraform side leaves the
origin willing to serve the leaver on the unbound canonical hostname, the exact path this build
defends. Worse, the lists had already drifted: Access allowed six, the origin allowed one.

**Drill 2 missed its own target, and that is the more useful result.** Steps 1–3 cost zero
downtime exactly as the create/distribute/revoke ordering predicts — both credentials returned
200 simultaneously. Then Terraform planned the token delete *before* the policy update that
released it, Cloudflare refused with `400 code 12139`, and recovery took two targeted applies:
35 seconds I had not budgeted because I had never run it. The runbook now says step 4 is two
applies, not one. The miss cost nothing real — the partner was already migrated, so 96 seconds
revoked a credential nobody legitimate was using. Reverse the ordering and they are 96 seconds
of a lab unable to deliver results.

## What I got wrong, and what it cost

**The one that reached production.** The booking form returned `{"error":"turnstile_missing"}`
for about twenty minutes and **the user found it, not me.** `.env.example` had no Turnstile
entry, so writing `.env` I invented a name — `TURNSTILE_SITEKEY` — while the code read
`TURNSTILE_SITE_KEY`. A `?? ''` default meant the page rendered fine with an empty sitekey and
failed only at submission. Two lessons: a fallback on a *required* value turns a startup failure
into a runtime one, and an incomplete `.env.example` is a bug waiting for someone to guess. The
sitekey is now required config.

**`error code: 1101` on every request after the first deploy.** Tailing the deployment showed
`DataError: Imported HMAC key length (0)`. Pages binds secrets at *deploy* time; I had set
`EDGE_HMAC_SECRET` afterwards, so the code held an empty key. Cost: most of the first live hour,
and far more without the tail — the symptom names no layer at all.

**The repo did not install for anyone but me.** The workspace catalog and two shared configs
lived in the parent directory: `ERR_PNPM_CATALOG_ENTRY_NOT_FOUND_FOR_SPEC` on a clean clone.
Found only because I cloned to a scratch path and ran install.

**The worst bug in the build, found by drill 5 and not by me.** The Function caches each
origin URL per isolate and drops it when the origin stops answering — except a dead quick tunnel
**does not throw** inside a Worker. Cloudflare answers the subrequest itself with 530, so
`fetch` resolves, the retry path never ran, and an isolate holding a stale URL served that 530
for the rest of its life. That is why the hostname alternated 200/530 by isolate. My retry was
correct and unreachable, which is the most expensive kind of wrong. Both the Function and the
supervisor's probe now key on the right signal: *any* HTTP status is healthy, because a 403 from
the origin means the whole path worked.

**An overclaim I retracted.** I described R28 — a service principal refused on a human route —
as demonstrable in production. It is not: Access refuses the token at the edge with a 302, so
the origin's check never fires. It is proven in the test suite, where the harness mints a token
for the console's own audience so `aud` cannot be what refuses it. The check is real; my account
of where you can watch it was wrong.

**Of the seven listed traps, none bit me** — R14's ordering, R21's header, R22's `aud` and
R29's per-IP counter were designed for from the start. What cost time was operational: a
variable name, deploy-time secret binding, a repo that only worked on the machine that wrote it,
and an error path that could not be reached. Roughly where real incidents come from, too.

## Not done, and why

§7 (SSH and WARP through Access, 7 points) and the firewall half of R6 need root on this box.
R8's connector is script-supervised, not a systemd unit — drill 5 is what that costs. R40 is
done: 12 resources destroyed and rebuilt in 291s with no dashboard click, and six
Cloudflare-issued identifiers changed underneath, which is the part that actually makes a
rebuild hard. Each remaining gap is named where it is missing rather than described as done.
