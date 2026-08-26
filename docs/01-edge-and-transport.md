# §1 — Edge and transport

R2 and R3 require a zone. This build takes the no-domain path (§11), so there is no zone to
configure Full (Strict) on, no Always Use HTTPS toggle, and no HSTS header of ours to set —
those are Cloudflare's to set on `pages.dev` and `trycloudflare.com`, not ours. The assignment
converts them to written answers, and that is what follows. R1, R4 and R5 are answerable
against the live system and are answered that way.

---

## R1 — Every public entry point is served over HTTPS by Cloudflare

Three hostnames reach application code. All three are Cloudflare-terminated and HTTPS-only;
none of them is a machine of ours with a certificate on it.

| Hostname | Terminated by | Plaintext possible? |
|---|---|---|
| `staff.<project>.pages.dev` (Access-bound preview alias) | Cloudflare | no |
| `<project>.pages.dev` (canonical, **not** Access-bound) | Cloudflare | no |
| `<random>.trycloudflare.com` (the origin's tunnel) | Cloudflare | no |

This is not a configuration I got right — it is a property of the path. `pages.dev` and
`trycloudflare.com` are Cloudflare-operated domains served only over HTTPS with HSTS already
set by Cloudflare. I cannot weaken it and I do not get credit for it.

What is worth saying is what happens *behind* the edge, because that is the part I do own.
The origin binds to `127.0.0.1` and speaks plain HTTP. That is not a downgrade: the only thing
that can reach it is `cloudflared` on the same host, over loopback, and the hop from Cloudflare
to `cloudflared` is a TLS connection that `cloudflared` opened outbound. There is no point on
the wire where a request exists in plaintext outside this machine's own kernel. Binding to
`0.0.0.0` and adding TLS would be strictly worse — it would create an inbound listener (GR1)
in exchange for encrypting a loopback hop that never leaves the box.

Proof:

```bash
# Every entry point answers on HTTPS and nothing answers on HTTP
curl -sI https://$CANONICAL | head -1
curl -sI http://$CANONICAL  | head -1      # 301 to https, issued by Cloudflare

# The origin is not a public entry point at all
ss -ltnp | grep -E '3000|3001|3002'         # all 127.0.0.1, never 0.0.0.0
```

---

## R2 — Full (Strict), and what Flexible actually does

**What I would set, and why.** Full (Strict) on the zone. It is the only mode in which the
padlock means what a visitor thinks it means.

**What Flexible actually does to the connection.** Flexible terminates TLS at Cloudflare and
then makes a **plain HTTP** request to the origin. The connection is therefore encrypted for
the leg the visitor can see and unencrypted for the leg they cannot. Concretely, on the
Cloudflare→origin hop the request travels as cleartext across whatever sits between them: the
origin host's datacentre network, its provider's backbone, any transit in between, and every
device with a tap on it. Session cookies, `Authorization` headers, form bodies, patient names —
all readable, and all *modifiable*, because an attacker positioned on that leg can rewrite the
response as easily as read it.

**Why the padlock is a lie.** The padlock is a statement about one hop. The visitor reads it as
a statement about the request. Those coincide under Full (Strict) and diverge completely under
Flexible, and nothing in the browser UI can tell the difference — the browser genuinely cannot
see past Cloudflare, which is the whole point of a reverse proxy. So Flexible produces a
security indicator that is *technically accurate and practically false*: it truthfully reports
that the browser's connection is encrypted while the data is being carried in the clear one hop
later. That is worse than no padlock, because no padlock at least prompts caution.

There is a second failure mode that gets less attention and bites harder. Flexible plus an
origin that also serves HTTPS and redirects HTTP→HTTPS produces an infinite redirect loop:
Cloudflare requests `http://`, the origin 301s to `https://`, Cloudflare passes the redirect
back, the browser retries, Cloudflare requests `http://` again. Engineers usually meet Flexible
here rather than through a threat model, fix the loop by disabling the origin's redirect, and
ship the cleartext hop permanently.

**Full vs Full (Strict).** Full encrypts the origin hop but accepts any certificate, including
self-signed and expired. That stops passive interception and does nothing about an active
attacker, who can present their own certificate and be believed. Strict validates the chain, so
the encrypted hop is also an authenticated one. The gap between Full and Full (Strict) is
exactly the gap between "encrypted" and "encrypted to the right party" — the same distinction
this whole assignment turns on at the identity layer.

**In this build.** The mode does not exist, because there is no origin certificate to validate:
the origin hop is a tunnel that `cloudflared` authenticated outbound, and the origin is on
loopback. That is Full (Strict)'s guarantee arrived at by removing the problem instead of
configuring around it — Cloudflare is not trusting a certificate my origin presents, it is
talking to a connector that proved itself to Cloudflare.

---

## R3 — Always Use HTTPS, HSTS, minimum TLS version

**What I would set:**

- **Always Use HTTPS** — on. Redirects `http://` to `https://` at the edge, so the plaintext
  request dies at Cloudflare rather than reaching anything.
- **Minimum TLS version — 1.2.** TLS 1.0 and 1.1 have no acceptable use in 2026 and are a PCI
  and HIPAA finding on sight. I would not force 1.3: the gain over 1.2 is real but modest, and
  the population it locks out of a *clinic booking page* — older Android handsets, corporate
  middleboxes — is exactly the population least able to route around the problem. Booking an
  appointment is not a place to make a point about cipher suites.
- **HSTS — `max-age=31536000; includeSubDomains`, preload deliberately OFF.**

**Justifying the max-age.** One year, because the security of HSTS *is* its max-age. The header
only protects a visitor who has already been to the site once over HTTPS; the window it covers
is the window between visits. A clinic's patients visit a few times a year, so a 6-month
max-age leaves a meaningful share of returning visitors unprotected on the visit that matters.
A year covers the realistic gap. The standard staged rollout — 300s, then a day, then a week,
then a year, watching for subdomains you forgot serve HTTP — is the right way to get there, and
`includeSubDomains` is the step that actually hurts if you rush it.

**What happens if I enable preload today and lose the domain in six months.**

This is the question, and the honest answer is: **a successor cannot serve the domain over
HTTP at all, for years, and I cannot undo it for them.**

Preload is not a header. It is an entry in a list compiled *into* Chrome, Firefox, Safari and
Edge binaries. Once shipped, every browser carrying that build refuses plaintext to the domain
before making any network request — no connection, no header, no opportunity to change its
mind. Removing the entry means requesting removal, waiting for it to be processed, waiting for
the next browser release, and then waiting for *users to install it*. The realistic tail is
months for most of the population and years for the rest: kiosks, unmanaged Android, embedded
browsers, anything that updates rarely or never.

So the six-month scenario plays out like this. The domain lapses. Someone else registers it —
a squatter, an ad network, or the next tenant of the name. They stand up a site. Every browser
that ever shipped with the preload entry demands HTTPS with a valid certificate for that
domain, and they will not get an interstitial or a warning they can click through, because
preload's failure mode is a hard failure, not a warning. If they cannot produce a certificate,
the domain is dark for those users. If they can — and with ACME, they can in a minute — they
inherit a domain that browsers now treat as *strictly more trustworthy* than an ordinary one.

The asymmetry is the point: **preload is a promise made by a name, not by an owner, and it
outlives the owner.** Enabling it commits every future holder of that name to a policy they
never agreed to, for a duration neither of us controls. For a clinic that might be acquired,
rebranded, or wound up, that is a bad trade for a marginal gain over a one-year HSTS header
that a returning visitor already carries. I would set the header at a year and leave preload
off until the domain is genuinely permanent — and "we plan to keep it" is not permanent.

---

## R4 — What `/cdn-cgi/trace` reveals, and where it fits in triage

`/cdn-cgi/trace` is served by Cloudflare's edge on every proxied hostname, from the datacentre
that handled the request, without touching the origin. Live example:

```
$ curl -s https://$CANONICAL/cdn-cgi/trace
fl=123f45
h=meridian-clinic.pages.dev
ip=203.0.113.9
ts=1756185600.123
visit_scheme=https
uag=curl/8.5.0
colo=BOM
sliver=none
http=http/2
loc=IN
tls=TLSv1.3
sni=plaintext
warp=off
gateway=off
rbi=off
kex=X25519
```

Field by field, the ones that matter:

| Field | What it reveals | Why I care |
|---|---|---|
| `ip` | the client IP **as Cloudflare sees it** | the value my rate limiter keys on (R29) |
| `colo` | the datacentre that served the request | which edge to blame; whether two clients are even on the same one |
| `loc` | country Cloudflare geolocated the IP to | matches the `country` claim I read off the Access JWT |
| `warp` | whether the request came through WARP | R35/R36 — proves enrolment without reading a policy |
| `gateway` | whether Gateway processed it | distinguishes "WARP is on" from "WARP is actually routing this" |
| `visit_scheme` / `http` / `tls` | scheme, protocol, TLS version negotiated | confirms R3's minimum-TLS in practice, not in the dashboard |
| `sni` | plaintext or encrypted | whether ECH is in play |
| `fl` / `ts` | edge request id and timestamp | the correlation key when asking Cloudflare support anything |

**Where it fits in triage — and the reason it is first.** It is the only check that returns a
useful answer *without involving my origin at all*. Every other probe I have conflates layers:
a `curl` to the app tells me something is broken but not whether it is Cloudflare, the tunnel,
the process, or the policy. `trace` isolates the edge cleanly.

So it is step 1 of R42's console-down triage, and it splits the problem in one request:

- **No response at all** → the problem is Cloudflare-side or DNS-side. Nothing downstream of the
  edge is worth looking at yet, and I have saved myself from debugging a healthy origin.
- **A response, with a redirect to the team domain instead of trace output** → Access is
  enforcing, the edge is fine, and the fault is in identity or policy — not infrastructure.
- **Clean trace output while the app 5xx's** → the edge is healthy and the fault is behind it:
  tunnel, process, or origin. That is where `cloudflared`'s own metrics and the origin's logs
  become the next question.

There is also an operational use that has nothing to do with outages: `warp=on` versus
`warp=off` is how I check WARP enrolment from any device without a management console, and
comparing `ip` here against what my rate limiter recorded is how I confirm the limiter is
keying on the address I think it is — which, behind CGNAT, it frequently is not.

---

## R5 — Was the origin IP ever published in DNS?

**No. Not once, and there is no window in which it could have been.**

This is provable from the architecture rather than from my memory of what I typed:

- There is **no zone** on this path, so there is no DNS record of mine anywhere to publish
  anything in.
- The origin has **never had an inbound listener**. It binds `127.0.0.1` on 3000/3001/3002
  (R7), so even a leaked address reaches nothing.
- The box is on a **hotspot behind CGNAT** with no public IP and no port forwarding (GR1).
  There is no stable address to have published.
- Reachability is provided by a **quick tunnel**, which is an outbound connection
  `cloudflared` establishes to Cloudflare. The public name is
  `<random>.trycloudflare.com`, whose DNS resolves to **Cloudflare's** anycast addresses. My
  address appears in no record, at any TTL.
- Consequently **nothing of mine is in Certificate Transparency**, because I have never
  requested a certificate. The certificate on `trycloudflare.com` is Cloudflare's, and it names
  Cloudflare's domain.

```bash
dig +short $TUNNEL_HOST            # Cloudflare anycast, never this box
curl -s "https://crt.sh/?q=%25.meridian-clinic.pages.dev&output=json" | head -c 200
ss -ltnp | grep -v 127.0.0.1       # no listener on any external interface
```

### The remedy, for the production case where the answer is "yes"

Most real systems answer yes, because they existed before they were behind Cloudflare. The
critical thing to internalise is that **this is not reversible.** Certificate Transparency is
append-only by design — that is what makes it useful — and passive DNS providers
(SecurityTrails, Shodan, Censys, RiskIQ) sell historical resolution precisely because it does
not expire. Turning on the proxy hides the *current* record and does nothing about the record's
history. An attacker running `crt.sh` against the apex, or pulling passive DNS for a
five-year-old `direct.example.com` or `mail.` or `vpn.` or `staging.`, has the origin address
in seconds. Assume any address ever published is public forever.

The remedy is therefore not concealment. It is **making the address useless to know**, in this
order:

1. **Change the origin IP.** Everything else is layered on the assumption that the old address
   is burned, because it is. This is the only step that actually invalidates what leaked, and
   it is the one people skip because it is disruptive.
2. **Refuse traffic that did not come through Cloudflare.** Firewall the origin to
   Cloudflare's published ranges, or better, use Authenticated Origin Pulls so the origin
   requires a client certificate Cloudflare presents — a range allowlist trusts anyone else's
   Cloudflare account, mTLS does not.
3. **Best of all, remove the inbound listener entirely** — a `cloudflared` tunnel, which is what
   this build does. Then the origin address is not merely filtered, it is unroutable, and the
   question "is the IP known?" stops having security consequences. Filtering is a control that
   can be misconfigured; having no listener is a property that cannot.
4. **Audit every subdomain, not just the apex.** The leak is almost never `www`. It is
   `mail`, `vpn`, `cpanel`, `direct`, `origin`, `old`, `staging`, `dev` — records nobody
   proxied because nobody remembered they existed. Enumerate from CT logs, which is the same
   list the attacker is working from.
5. **Prevent the recurrence at issuance.** Use DNS-01 wildcard certificates rather than
   per-host HTTP-01, so individual internal hostnames stop being announced to a public
   append-only log every ninety days.

The general lesson, which is the same one R21 teaches at the identity layer: a control that
depends on an attacker not knowing something is not a control. It is a delay, and CT logs have
made the delay approximately zero.
