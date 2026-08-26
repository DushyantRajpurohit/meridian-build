# The Meridian Build — Assignment 3

Three Node surfaces on a box with no public IP, reachable through Cloudflare, each gating
itself on a token it verifies rather than on where the request arrived from.

Running the **free path** from §11: Cloudflare Pages + a Pages Function proxying to a quick
tunnel. That path is the harder one on purpose — the Pages Access toggle protects the
hash-based preview URLs and not the canonical `<project>.pages.dev`, so R16 has a real gap in
it and R24 has a live bypass to close, and the origin sits behind a public
`trycloudflare.com` URL with no "nobody can reach it anyway" to fall back on.

## Status

| Section | State |
|---|---|
| §1 Edge and transport (R1–R5) | **written** — R2/R3 are written answers on this path, see `docs/` |
| §2 Connectivity (R6–R11) | R7/R9/R11 **written**, R7 verified against `cloudflared`; R6 needs `ufw` (root); R8 needs a named tunnel; R10 unavailable on this path |
| §3 Identity and policy (R12–R16) | **live** — OTP IdP, both applications, Block above Allow verified at Cloudflare |
| §4 Origin enforcement (R17–R24) | **live** — both R24 bypass routes closed with the origin's own refusals |
| §5 Machine-to-machine (R25–R28) | **live** — a real service token reads the partner API end to end |
| §6 Public surface (R29–R32) | **live** — rate limit, user-agent rule and Turnstile all firing at the edge |
| §8 Infrastructure as code (R37–R40) | **applied** — 10 resources, plan clean; R40's destroy/rebuild not yet exercised |
| §9 Ops and threat model (R41–R43) | R43 **written**; R42's runbooks written but not timed; R41 needs the audit-log pull |
| §7 Operational access (R33–R36) | not started — needs `sshd` and root |
| §11 free-path plumbing | **deployed** — Function, edge signature and three quick tunnels live |

**38 tests green** on Node 24, none of which need a Cloudflare account.

## What is here

```
src/access/jwks.ts        R18  team JWKS, fetched and cached by us — TTL, rotation, floor
src/access/verify.ts      R19  signature, iss, exp, aud. The forty lines.
src/access/middleware.ts  R17  header then cookie; R20 one door; R21 forgeable headers deleted
src/apps/admin.ts         :3001 staff console, renders the verified principal
src/apps/partner.ts       :3002 partner lab, service principals only
src/apps/public.ts        :3000 booking page, Turnstile, signed lab webhook
src/hmac.ts               R32  HMAC over raw body + timestamp, constant-time, replay window
test/harness.ts                a local Zero Trust team: mints genuine, forged and cross-aud tokens
scripts/cross-audience.ts R22  the two outputs, side by side
src/access/edge.ts             proof a request came through the Function; never identity
scripts/forge.ts          R23  mints $FORGED_JWT for the acceptance suite
scripts/publish-origins.ts     supervises the quick tunnels, republishes their URLs to KV

pages/functions/[[path]].ts    the reverse proxy from §11's diagram
pages/functions/_lib/sign.ts   HMAC over the hop to a public quick tunnel
pages/functions/_lib/ratelimit.ts  R29 two counters; R30's rule is in [[path]].ts
pages/functions/_lib/origin.ts     finds the current quick tunnel URL in KV
```

## The free path, and why the origin signs

Access is bound to the Pages project, which protects the **preview** hostnames and not the
canonical `<project>.pages.dev`. Meanwhile the origin answers on a public
`trycloudflare.com` URL. So there are two ways to reach the application without passing
Access, and both are closed at the origin rather than at the edge:

| Hostname | Access bound? | What reaches the origin | Result |
|---|---|---|---|
| `staff.<project>.pages.dev` (preview alias) | yes | signed request + Access JWT | 200 |
| `<project>.pages.dev` (canonical) | **no** | signed request, no token | **403 `no_token`** |
| `<random>.trycloudflare.com` (origin) | n/a | unsigned request, any headers | **403 `edge_nonce_missing`** |

The signature on the middle hop proves a request travelled through the Function. It proves
nothing about who sent it, it runs *before* the token check and never in place of it, and the
second row above is the proof: a perfectly signed request with no token is still refused.
Without it, though, the rate limiter, the filtering rule and the Access application are all
bypassable by anyone who learns the quick-tunnel URL — the origin has no other way to tell.

## Proving it (GR5)

The enforcement path has a regression suite rather than a screenshot, and it needs no
Cloudflare account — the harness mints its own tokens against a local key pair. Everything
below runs from a clean clone of this repository:

```bash
nvm use            # Node 24, per .nvmrc — wrangler needs >= 22
pnpm install
pnpm test          # 38 tests: R17–R24, R26–R32
pnpm typecheck
pnpm lint
```

R22, both outputs, reproducible by a reviewer with no access to our team:

```bash
pnpm exec tsx scripts/cross-audience.ts
```

A local dress rehearsal of the assignment's own acceptance suite — the real apps on the real
ports, the real `JwksCache` fetching over real HTTP from a JWKS served on loopback, driven
over real sockets. The only fakes are the things Cloudflare would issue:

```bash
pnpm rehearse            # 16 checks
pnpm rehearse -- --serve # leave it up and curl by hand
```

```
  REF    EXPECT  GOT   REASON                              CHECK
  R20    403     403   no_token                            no token, through the edge
  R20    403     403   malformed                           malformed token
  R20    403     403   expired                             expired token
  R23    403     403   bad_signature                       forged signature, real kid
  R22    403     403   wrong_audience                      token minted for the partner API
  R21    403     403   no_token                            spoofed identity header alone
  R24    403     403   edge_nonce_missing                  straight to the origin, no edge signature
  R24    403     403   edge_nonce_missing                  straight to the origin, booking endpoint
  R26    200     200   -                                   service token reads the partner API
  R28    403     403   service_principal_on_human_route    service token on the staff console, scoped to it
  R27    403     403   not_a_service_principal             staff token on the machine-only partner route
  R21    200     200   dr.okafor@meridian.test             valid token + header claiming ceo@meridian.test
  R31    400     400   turnstile_failed                    booking with a junk Turnstile token
  OK     200     200   -                                   genuine staff token reaches the console
  R32    202     202   -                                   signed webhook delivery
  R32    401     401   replayed                            the same delivery replayed
```

Two lines there are worth reading twice. **R28** is a service token minted *for the staff
console's own audience*, so `aud` cannot be what refuses it — the origin refuses it for being
a machine on a human route, which is the actual requirement. **R21** reports the viewer the
console rendered: the request carried a header claiming `ceo@meridian.test` and the console
said `dr.okafor@meridian.test`, because it read the token and not the header.

**R31 is a real round trip.** The rehearsal calls Cloudflare's live `siteverify` with a junk
token and Cloudflare rejects it. It is not the fail-closed path returning 400 by accident.

### Seeing it in a browser

`--serve` also starts two local stand-ins for the Pages Function (`scripts/local-edge.ts`),
which run the deployed code where it counts — `gate()` for R29/R30 and `signForOrigin()` for
the hop — so the local demo cannot drift away from what is deployed.

```
http://127.0.0.1:8080/          booking page — public, 200
http://127.0.0.1:8080/admin     staff console — 403 no_token
http://127.0.0.1:8081/admin     staff console — 200, renders dr.okafor@meridian.test
http://127.0.0.1:3001/          origin direct  — 403 edge_nonce_missing
```

`:8080` stands for the canonical `<project>.pages.dev`, which the Pages Access toggle does
**not** protect; `:8081` for the preview alias, which it does. Same origin, same code, same
request — the only difference is whether a token came with it. That is R16 and R24 side by
side, in a browser.

`:8081` injects an assertion the way Access would. That is a simulation of the identity
provider and of nothing else: the origin still verifies signature, issuer, expiry and
audience on every request, and nothing in `src/` knows `local-edge.ts` exists.

R29 and R30 exercised over real sockets for the first time:

```
$ curl -A '' -X POST :8080/book -d 'name=x'
{"error":"no_user_agent"}                                              # R30

$ for i in $(seq 1 8); do curl -X POST :8080/book -d 'name=x&cf-turnstile-response=z'; done
400 400 400 400 400 429 429 429                                        # R29, device counter at 5
```

The 400s are Turnstile refusing a junk token; the 429s are the narrow counter tripping after
five. Both codes on the same endpoint, which is the design: the limiter keeps volume off the
check, and the check is what decides whether a booking is real.

What still cannot be covered locally: §2, §7, §8 and §9 all need an account.

## Notes to carry into the writeup

- **R18 cache.** TTL 15 minutes; an unknown `kid` forces a refetch so a rotation costs one
  fetch rather than up to a TTL of 403s; that forced path is floored at one refetch per 10
  seconds so unknown kids cannot amplify requests at Cloudflare. The floor was 60 seconds
  first, which priced a real availability risk against an amplification risk that 10 seconds
  already closes.
- **R7 trap, pre-empted.** `BIND_HOST` defaults to the literal `127.0.0.1`. `localhost` can
  resolve to `::1` first, and an IPv4-only listener then produces an intermittent 502 that
  reads as a Cloudflare fault.
- **R21.** Five forgeable identity headers are deleted on the way in, so no handler, template
  or log line downstream can read one and mistake it for identity.
- **R27.** `Principal` is a union, not a user object with an optional email. A service token
  cannot be read as a person because there is no field on it to misread.

- **The Worker and the origin sign identically.** `test/edge.test.ts` imports the Function's
  own `signForOrigin` rather than reimplementing it, so the suite proves the Web Crypto HMAC
  in the Worker and the `node:crypto` HMAC at the origin agree byte for byte, instead of that
  first being discovered in production.
- **R29 counts a device, not an IP.** Two counters: `sha256(ip|user-agent)` at 5 per 10 min,
  and IP alone at 60 per 10 min. A waiting room full of patients on one NAT has many device
  signatures and never trips the narrow counter; a script flooding `/book` is one signature
  and exhausts it in seconds. Neither is identity — Turnstile is what decides whether a
  booking is real; these only keep volume off it.
- **KV is the wrong primitive for a counter and is used anyway.** Read-modify-write over an
  eventually-consistent store undercounts under a parallel burst. Durable Objects are correct;
  §11 names KV, so KV is what this uses, and this sentence is in the writeup rather than
  omitted from it.
- **R10 is not available on this path.** A quick tunnel has no credentials file and no ingress
  table, so two connectors cannot serve one tunnel. That is a real cost of the free route.


## Live (§3, §5, §6 proven against Cloudflare)

Deployed and verified end to end. Every line below was run against the real system, not the
rehearsal.

| Hostname | Access bound? | Result | Requirement |
|---|---|---|---|
| `staff.meridian-clinic.pages.dev` | **yes** | 302 to `dushyant-singh.cloudflareaccess.com`, `kid` == `ACCESS_AUD_ADMIN` | R13 |
| `api.meridian-clinic.pages.dev` | **yes** (service tokens only) | 403 with no redirect — a `non_identity` policy has no login flow | R25 |
| `meridian-clinic.pages.dev` | **no** | serves the public page; `/admin` returns **403 `no_token`** from the origin | R16, R24 |
| `<random>.trycloudflare.com` ×3 | n/a | **403 `edge_nonce_missing`** | R24 |

```
  REF    EXP  GOT  BODY / REASON                          CHECK
  R1     200  200  <!doctype html>…                       public booking page
  R24    403  403  {"error":"forbidden","reason":"no_token"}   canonical host is not Access-bound
  R13    302  302  302 to the team domain                 Access gates the console at the edge
  R25    403  403  Access denial page                     partner API, no service token
  R26    200  200  {"results":[{"id":"lr-001",…           service token reads the partner API
  R24    403  403  {"error":"forbidden","reason":"edge_nonce_missing"}  straight to the origin
  R21    403  403  {"error":"forbidden","reason":"edge_nonce_missing"}  forged identity header alone
  R30    403  403  {"error":"no_user_agent"}              no user agent
  R31    400  400  {"error":"turnstile_failed"}           junk Turnstile token, live siteverify
  R29    429  429  {"error":"too_many_requests"}          6th booking from one device
```

**R26 is the whole machine path in one request:** service token → Access → Pages Function →
HMAC-signed hop → quick tunnel → origin → JWT verified against the live team JWKS → 200.

### Three things that did not go to plan, recorded rather than tidied away

**Pages binds secrets at deployment time.** Setting `EDGE_HMAC_SECRET` after deploying left the
running Function with an empty key, and it threw `DataError: Imported HMAC key length (0)` —
surfacing as a bare `error code: 1101` with no clue in it. A redeploy fixed it. The lesson is
ordering: a Pages secret is not live configuration, it is baked into the next deployment.

**`staff.` and `api.` are preview aliases, and Pages only serves those for branches that have a
deployment.** Access was bound to both hostnames and denied unauthenticated requests correctly,
so the edge looked healthy — but past Access there was no deployment, and an authenticated
service token got a Cloudflare 404. Deploying `--branch staff` and `--branch api` created the
aliases. A hostname can be Access-protected and serve nothing; the 403 proves the policy, not
the application.

**R29's counter is eventually consistent, and it showed.** Bookings 6 and 7 were correctly
refused with 429; booking 8 was allowed through again. That is KV converging, not a coding
error, and it is the limitation already written into `_lib/ratelimit.ts` and the threat model —
observed live rather than merely predicted. The limiter raises the cost of abuse; it does not
impose a hard ceiling.

### R28, precisely

A service token presented to the staff console is refused — but by **Access at the edge**, with
a 302 to the login flow, because no `non_identity` policy is attached to that application. The
request never reaches the origin, so the origin's own
`service_principal_on_human_route` refusal cannot be demonstrated in production. It is proven
in the test suite instead, where the harness mints a service token *for the staff console's own
audience* so that `aud` cannot be what refuses it. Both layers refuse; only one of them can be
shown live, and it is the outer one.

## Written answers

Several requirements ask for an explanation rather than a running system, and on the no-domain
path (§11) a few more become written answers because there is no zone to configure. They live
in `docs/` rather than inline here, so this README stays a thing a reviewer can walk top to
bottom.

| Document | Covers |
|---|---|
| [`docs/01-edge-and-transport.md`](docs/01-edge-and-transport.md) | R1–R5. What Flexible TLS actually does to the connection; the HSTS-preload-and-lose-the-domain question; `/cdn-cgi/trace` in triage; whether the origin IP was ever published, and the production remedy when the answer is yes |
| [`docs/02-connectivity.md`](docs/02-connectivity.md) | R6–R11. Why a missing ingress catch-all stops `cloudflared` from starting rather than producing a 404; credentials file vs connector token and which is worse to leak; 1033 vs 1016 vs origin 502, and what each accuses |
| [`docs/41-audit-logs.md`](docs/41-audit-logs.md) | R41. The audit log pulled as JSON — and why two of the three things R41 asks for are absent from it, permanently. Access logs identity events, not refusals |
| [`docs/42-incident-runbooks.md`](docs/42-incident-runbooks.md) | R42. Four procedures, written before being timed. Drill 4 performed against the live system and timed; 1 and 2 blocked on an apply, and say so |
| [`docs/43-threat-model.md`](docs/43-threat-model.md) | R43. Assets, actors, what this stops — and the longer list of what it does not |
| [`WRITEUP.md`](WRITEUP.md) | The ≤1500-word deliverable: threat model, incident timings, and what I got wrong and what it cost |

## Infrastructure as code (§8)

Terraform 1.15.9, Cloudflare provider 5.24.0. `terraform validate` passes and `terraform plan`
against the live account reports **10 to add, 0 to change, 0 to destroy**.

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars    # then fill it in
terraform init
./tf.sh plan
./tf.sh apply
./tf.sh destroy && ./tf.sh apply                # R40, with no dashboard click in between
```

`tf.sh` is the only path to the API. It lifts the scoped token out of `.env` (mode 600,
gitignored) into `CLOUDFLARE_API_TOKEN` for the provider, so the token never reaches a shell
history, an argument list, or a `.tf` file. There is no Global API Key anywhere, and the
provider is not configured to accept one.

What it manages, all ten resources:

| Resource | Requirement |
|---|---|
| Workers KV namespace | rate-limit counters (R29), tunnel URL republishing |
| Pages project | the site and its Function |
| One-time PIN identity provider | R12 |
| Turnstile widget | R31 |
| Access service token (partner lab) | R25 |
| Access policy — Block former staff | R14, precedence 1 |
| Access policy — Allow staff | R13, precedence 2 |
| Access policy — partner Service Auth (`non_identity`) | R25 |
| Access application — staff console | R13/R14/R15 |
| Access application — partner API | R25/R28 |

The identity provider is declared rather than left as the account default specifically so that
R40's `destroy` → `apply` cycle rebuilds the login method too. Turnstile is account-scoped, so
unlike a WAF ruleset it is available with no zone.

### R38 — the exact token scopes

Account-level, eight permissions, **no zone permissions at all** — there is no zone on the
free path, which is a genuine reduction in blast radius rather than a shortcut:

| Permission | Level | Needed for |
|---|---|---|
| Cloudflare Pages | Edit | the site and its Function |
| Workers KV Storage | Edit | rate-limit counters, tunnel URLs |
| Access: Apps and Policies | Edit | the two applications and three policies |
| Access: Service Tokens | Edit | the partner lab's credentials |
| Access: Organizations, Identity Providers, and Groups | Edit | the login method |
| Access: Audit Logs | Read | R41 |
| Cloudflare Tunnel | Edit | R37 |
| Turnstile | Edit | the booking widget |

A Global API Key is an automatic failure and is not used anywhere. The token carries a 32-day
TTL and no client-IP restriction (this box is on a hotspot with a changing address).

### What §8 cannot cover on this path, and why

- **R37 names DNS records and security rulesets.** There is no zone, so there are no DNS
  records to manage and no `cloudflare_ruleset` to attach one to — WAF custom rules are a
  zone-level object. Nothing is being skipped: the resources genuinely do not exist in this
  architecture. The account-level equivalents that *do* exist are in the plan — Turnstile for
  the public form, and the rate limiting the Function enforces in KV rather than at the WAF.
- **R39 is about the tunnel config resource being a full replace rather than a merge.** A
  quick tunnel has no ingress table, so there is no `cloudflare_zero_trust_tunnel_cloudflared_config`
  in this plan and no hand-made rules for a first apply to silently delete. The trap is real
  and is answered in writing rather than demonstrated.
- **The Pages Access binding is the open question.** The assignment notes that `*.workers.dev`
  cannot be placed behind Access because the self-hosted application form only offers zones you
  own, and `pages.dev` is not one either. Whether the API accepts a `pages.dev` domain where the
  dashboard refuses it is not answerable from a plan — only an apply settles it. If it refuses,
  the fallback is the Pages settings toggle, which is a dashboard control and would be an
  honest, documented exception to GR4 rather than a silent one.

## Not yet true

Honest ledger of what is still outstanding:

- **§7 (R33–R36) is untouched.** `sshd` is inactive on the box and enabling it needs root, so
  SSH through Access, the LAN-rule deletion and reboot, and WARP enrolment are all ahead.
- **R6's firewall half.** No non-loopback listener exists and every surface binds `127.0.0.1`,
  but `ufw default deny incoming` needs root and has not been set.
- **R40 has not been exercised.** The plan is clean and the configuration is complete, but
  `destroy` followed by `apply` has not actually been run end to end.
- **R42's drills 1 and 2 are untimed.** Both need a `terraform apply` to perform, so the
  procedures are written and ordered but carry no number. Drill 4 has been run and timed
  (3s to diagnose, 14s to recover). R41's pull is done and is in `docs/41-audit-logs.md`.
- **R8** needs a named tunnel with a systemd unit; the three quick tunnels here are supervised
  by a script and do not survive a reboot unattended. The supervisor now probes each published
  hostname every 60s and rebuilds a connector whose hostname has been reaped — see drill 5,
  the incident that proved it was needed — but a probe is not `Restart=always`, and nothing
  here starts at boot.
- **The reviewer's test identity and the recording** are outstanding.

The staff Allow list is six Gmail plus-addresses that all deliver to one inbox. That proves the
policy scopes per-identity; it does not prove six independent people exist. Under one-time PIN
the inbox *is* the identity, so those six are one identity in security terms — see the threat
model, which says so about itself.

## Toolchain

`cloudflared` 2026.8.2 (in `~/.local/bin`) and `wrangler` 4.126.0 (a devDependency of this repo,
pinned to an exact version — see below for why this repo does not use the parent catalog).

Wrangler 4 requires **Node 22 or newer**; this box was on Node 20, so the project pins Node 24
in `.nvmrc`. Run `nvm use` in this directory before `pnpm deploy`. The catalog was already
typing against `@types/node ^24`, so this closes a gap where the types and the runtime
disagreed. `pnpm test`, `pnpm typecheck` and `pnpm lint` all pass on Node 24.

**Note:** `workerd` is in `onlyBuiltDependencies` for the same reason `esbuild` is: it fetches a
platform binary in a postinstall, and without the approval `wrangler pages dev` cannot start.

### Why this repo does not use the parent workspace's catalog

The other five JS projects in this repository's parent directory share a pnpm catalog, so a
dependency has one version across all of them. This project deliberately does not: it ships as
its own public repository, and a reviewer clones *this* directory, not its parent. With
`catalog:` references, `pnpm install` in a fresh clone fails with
`ERR_PNPM_CATALOG_ENTRY_NOT_FOUND_FOR_SPEC` — which I found by cloning to a scratch path and
running it, rather than by assuming it worked.

So the versions here are the exact ones the catalog resolved to, `tsconfig.base.json` and
`.oxlintrc.json` are vendored rather than referenced one level up, and
`pnpm.onlyBuiltDependencies` is repeated in `package.json`. Pinning exactly is the right
default for a submitted artifact anyway: it is pinned to what was actually tested.

Verified end to end — a clean clone with no parent directory present installs, then passes 38
tests, both typecheck programs, and lint.
