# R41 — Access audit logs, pulled as JSON

Pulled via the API, not screenshotted:

```bash
curl -s -H "Authorization: Bearer $CF_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/access/logs/access_requests?limit=100" \
  | jq '.result[] | {created_at, allowed, user_email, app_domain}'
```

The token's `Access: Audit Logs — Read` scope exists for exactly this call and nothing else.

## What R41 asks me to locate, and what I actually found

R41 names three things to find. Only one of them is there, and **the reason the other two are
missing is the most useful thing this section produced.**

| R41 asks for | Present? | Why |
|---|---|---|
| The service-token calls | **yes** | `allowed=true`, client id `e461d898…access`, `app_domain: api.meridian-clinic.pages.dev/v1/results` |
| My own logins | not yet | No human has completed a one-time PIN login against the console at the time of writing |
| The denied forged-token attempt from R23 | **no — and it never will be** | See below |

## Why the forged-token denial is absent

The R23 forgery was presented to `meridian-clinic.pages.dev`, the canonical Pages hostname that
Access is **not** bound to (R16). So the request never passed through Access at all. It reached
the Pages Function, was signed onto the origin, and the origin refused it:

```
{"error":"forbidden","reason":"bad_signature"}
```

Access cannot log a decision it was never asked to make. The refusal is recorded in the
origin's own log instead:

```
[admin] deny  bad_signature GET / -
```

I also tried to force an Access-level denial by presenting first a valid and then a bogus
service token to the staff console. Both returned 302 to the login flow, and **neither appeared
in the audit log.**

## The generalisation, which is the point

**Cloudflare's Access audit log records identity events, not request denials.** It answers "who
authenticated, when, and to what" — a completed login, a service token accepted. It does not
answer "what was refused". An unauthenticated request bounced to the login page is not an
authentication event, so it is not logged; nor is anything Access never saw.

That has a direct consequence for this architecture, and it is uncomfortable in a way worth
stating plainly: **every security-relevant refusal in this build is invisible to Cloudflare's
audit log.** The forged signature, the missing token at the origin, the wrong audience, the
service principal on a human route, the unsigned request straight to the tunnel — all of them
are enforced at the origin, by design, precisely because the edge cannot be the only thing
standing there. The corollary is that the origin's log is the only place they exist.

So an incident review that reaches for the Cloudflare dashboard sees a clean, quiet account
while an attacker is being refused hundreds of times a minute. The two sources are not
alternatives; they answer different questions:

| Question | Source |
|---|---|
| Who logged in, and when? | Access audit log |
| Which machine identities called what? | Access audit log |
| What was refused, and for which of the eight reasons? | The origin's log |
| Did anyone reach the origin around the edge? | The origin's log, only |

**What I would do about it in production**, and have not done here: ship the origin's denial
log somewhere durable and queryable, and alert on the ratio of `bad_signature` and
`edge_nonce_missing` rather than on their presence — a steady trickle of `no_token` is the
internet knocking, while a spike in `bad_signature` means somebody has a real `kid` and is
trying keys. Right now that log is a file on one box, which is a real gap and is named as one
in the threat model.
