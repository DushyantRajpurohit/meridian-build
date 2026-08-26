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
| §4 Origin enforcement (R17–R24) | **built, tested** — including R24 against both bypass routes |
| §5 Machine-to-machine (R25–R28) | origin half built and tested; needs a real service token |
| §6 Public surface (R29–R32) | **built, tested** — rate limiter and filtering rule in the Pages Function, Turnstile and webhook signature at the origin |
| §11 free-path plumbing | Pages Function, edge signature and the tunnel supervisor written; nothing deployed |
| §1–§3, §7–§9 | not started — all need a Cloudflare account |

**38 tests green**, none of which need a Cloudflare account.

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
Cloudflare account — the harness mints its own tokens against a local key pair.

```bash
pnpm --filter assignment-3-meridian-build test          # 38 tests: R17–R24, R26–R32
pnpm --filter assignment-3-meridian-build typecheck
pnpm --filter assignment-3-meridian-build lint
```

R22, both outputs, reproducible by a reviewer with no access to our team:

```bash
pnpm --filter assignment-3-meridian-build exec tsx scripts/cross-audience.ts
```

A local dress rehearsal of the assignment's own acceptance suite — the real apps on the real
ports, the real `JwksCache` fetching over real HTTP from a JWKS served on loopback, driven
over real sockets. The only fakes are the things Cloudflare would issue:

```bash
pnpm --filter assignment-3-meridian-build rehearse            # 16 checks
pnpm --filter assignment-3-meridian-build rehearse -- --serve # leave it up and curl by hand
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

Nothing here has met Cloudflare. There is no account, no tunnel, no Access application, and
`cloudflared`, `terraform` and `wrangler` are not installed on the box. The enforcement code
is written against the token format and proven against a local team that mints the same
shape; the live half of every requirement is still ahead.
