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
distinguish a compromised mailbox from a legitimate one because there is no difference to tell.
The service token is a bearer credential with no proof of possession. An authorised user
exporting everything on their last morning looks like one doing their job. Anyone with the API
token can rewrite the posture, and Terraform makes that faster, not slower. Every check here
answers "who is this?" and none answers "should this request be allowed?" — a validly
authenticated partner posting a hostile lab result is inside every control here. And if the box
is compromised, Zero Trust protected the path to the origin, not the origin.

One more, observed rather than theorised: KV rate-limit counters are eventually consistent. I
predicted that in writing, then watched request 8 get through after 6 and 7 were correctly 429'd.

## Incident timings

- **Drill 4, staff console down** — five-step triage: **3s to diagnose, 14s to recover.**
- **Drill 5, unplanned** — the tunnels died on their own: **~90s to diagnose, 53s to recover.**
- **Drill 1, staff leaver** — revoke *and* terminate the session: blocked on `terraform apply`.
- **Drill 2, leaked service token** — rotate under 60s: blocked on `terraform apply`.
- **Drill 3, tunnel token leaks** — n/a on this path.

Drill 4 ran against the live system with the origin killed deliberately. Step 1 (edge) showed
`colo=BOM`; step 2, the connectors alive; step 3, no listener on 3000–3002. Steps 4 and 5 were
never reached — the runbook working, because the fault was infrastructure and the ordering meant
I never opened a policy page.

**That number is small because the fault was** — I killed a process on a box I was already
logged into. The drill establishes the ordering, not the duration.

Drill 5 was not a drill. Checking the URLs before submission, the public hostname returned 530
while the Access-bound two still gave 302 and 403 — they never reach the origin, so only the
public one could show it. The three `cloudflared` processes were **still running**: the quick
tunnel hostnames had been reaped at Cloudflare's end, and `curl` returning `000` rather than a
status was the tell, because that is DNS failing. A live connector process is not a live tunnel.
Nothing crashed — the system went dark on its own schedule while I was not looking, which is
exactly why R8 asks for a managed service.

Drills 1 and 2 are written and ordered — 2's trick is create/distribute/revoke, so the
sixty-second clock covers only the final revoke — but they are untimed, because they need an
apply I could not run. I will not claim a number I did not measure.

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
Found only because I cloned to a scratch path and ran install rather than assuming. A repo a
reviewer can follow is a deliverable, and mine was broken for every reader.

**The worst bug in the build, found by drill 5 and not by me.** The Function caches each
origin URL per isolate and drops it when the origin stops answering — except a dead quick tunnel
**does not throw** inside a Worker. Cloudflare answers the subrequest itself with 530, so
`fetch` resolves, the retry path never ran, and an isolate holding a stale URL served that 530
for the rest of its life. That is why the hostname alternated 200/530 by isolate. My retry was
correct and unreachable, which is the most expensive kind of wrong. Both the Function and the
supervisor's liveness probe now key on the right signal: the probe treats *any* HTTP status as
healthy, because a 403 from the origin means the whole path worked.

**Two Terraform drifts, found by re-planning after the first apply** — the habit, not the
finding. Cloudflare returns the Turnstile `domains` list sorted and Terraform compares lists
positionally, so an unsorted config diffs forever; and the partner application had silently
inherited the provider's default session duration, making R15's "deliberate choice" really
"whatever the provider picked".

**An overclaim I retracted.** I described R28 — a service principal refused on a human route —
as demonstrable in production. It is not: Access refuses the token at the edge with a 302, so
the origin's check never fires. It is proven in the test suite, where the harness mints a token
for the console's own audience so `aud` cannot be what refuses it. The check is real; my account
of where you can watch it was wrong.

**Of the seven listed traps, none bit me** — R14's ordering, R21's header, R22's `aud` and
R29's per-IP counter were designed for from the start. What cost time was operational: an
environment variable name, deploy-time secret binding, a repo that only worked on the machine
that wrote it, and an error path that could not be reached. Roughly where I would expect real
incidents to come from, too.

## Not done, and why

§7 (SSH and WARP through Access, 7 points) and the firewall half of R6 need root on this box.
R40's rebuild and R42's first two drills need a `terraform apply` I cannot run myself. R8's
connector is script-supervised, not a systemd unit — drill 5 is what that costs. Each is named
where it is missing rather than described as done.
