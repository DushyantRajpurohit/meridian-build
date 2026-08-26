# R42 — Four procedures, performed and timed

Each runbook is written before it is executed, then executed against the live system with a
wall clock, and the **measured** time recorded honestly — including the time spent on the wrong
step. The times below are recorded on execution; unfilled rows are not yet run and say so.

| # | Procedure | Target | Measured |
|---|---|---|---|
| 1 | Staff member leaves — revoke and terminate live session | — | _not yet run_ |
| 2 | Service token in a public paste — rotate | **< 60s** partner downtime | _not yet run_ |
| 3 | Tunnel token leaks — assess and respond | — | _not yet run_ |
| 4 | Staff console down — five-step triage | — | _not yet run_ |

---

## 1 — A staff member leaves

**The trap:** removing someone from the Allow policy stops them getting a *new* session. It
does nothing to the session they are holding right now, which under R15 can be valid for
another eight hours. Revocation and termination are two separate actions and only one of them
is obvious.

1. Remove the address from `staff_emails` in `terraform.tfvars`.
2. `./tf.sh apply` — the Allow policy no longer includes them. **New** logins now fail.
3. Add the address to `blocked_emails` as well. This matters more than it looks: the Block sits
   at precedence 1, so it denies them even if a future edit, a group membership, or a mistake
   puts them back in an Allow. Removal is the absence of permission; the Block is the presence
   of a denial, and only the second survives someone else's error.
4. **Terminate the live session** — the step people miss. Cloudflare Access revokes a user's
   active sessions from the Zero Trust user registry. In the API this is the
   `/access/organizations/revoke_user` call against the account, by email.
5. Verify: their existing `CF_Authorization` cookie now fails. The origin will reject it
   independently of the edge once it expires, but revocation is what makes that immediate
   rather than eventual.
6. Rotate anything they held that is not identity-bound — shared secrets are not revoked by
   removing a person.

**Why the Block, given the Allow no longer matches them:** defence against the *next* edit, not
this one. R14's ordering exists precisely so that a deny is not silently overridden later.

---

## 2 — The service token appears in a public paste

**Constraint: partner integration down for under sixty seconds.** That constraint is the whole
exercise, because the naive order — delete the old token, create a new one, tell the partner —
guarantees a multi-minute outage while the partner updates their config.

The order that meets the constraint is **create, distribute, then revoke**:

1. **Before touching the old token**, add a second service token in Terraform and apply. Both
   tokens are now valid; the partner API accepts either. Downtime so far: zero.
2. Attach the new token to the partner policy alongside the old one, or add a second
   `non_identity` policy scoped to it.
3. Hand the new client id and secret to the partner over a channel that is not the one that
   leaked, and wait for them to confirm they are using it. **This wait costs nothing**, because
   the old token still works — which is the entire point of the ordering. The clock that matters
   has not started.
4. **Now** remove the leaked token from the policy and destroy it. This is the only step that
   interrupts anything, and it interrupts only callers still using the leaked credential —
   which, after step 3, is nobody legitimate.
5. Verify: a call with the leaked token returns 403; a call with the new token returns 200.

The measured sixty seconds is step 4 alone, and it is short because steps 1–3 removed every
reason to hurry. Reversing the order turns a sixty-second window into however long the partner
takes to answer email.

**Caveat to record honestly:** the leaked token was valid for the entire interval between the
paste appearing and step 4 completing. Rotation limits future damage; it does not undo access
already taken. The audit-log pull in R41 is how I find out what was done with it.

---

## 3 — The tunnel token leaks

**What an attacker can actually do with it — precisely.**

A tunnel token authenticates a *connector* to Cloudflare for a named tunnel. With it, an
attacker can run their own `cloudflared` and register as an additional connector for my tunnel.
Cloudflare load-balances across healthy connectors, so a share of production traffic for my
hostname is then routed to **their** machine. They can serve whatever they like to my visitors
under my hostname and Cloudflare's certificate — a convincing credential-harvesting page for
staff, or silently altered lab results.

What it does **not** give them, and this is why the blast radius is smaller here than it would
usually be:

- It is not inbound access to my box. It authenticates a connector *to Cloudflare*; it does not
  let anyone connect *to me*.
- It does not bypass Access. Requests still hit the Access-bound hostname and still require a
  valid token. An attacker serving traffic through a hijacked connector receives requests that
  already passed Access — they can respond maliciously, but they cannot mint identity.
- It does not yield the origin's secrets. `EDGE_HMAC_SECRET` is not in the tunnel token, so
  their connector cannot produce a validly signed request to my origin — though it does not
  need to, since it is answering requests rather than forwarding them.

The realistic damage is therefore **integrity and impersonation of the origin**, not
confidentiality of what is at rest. That is bad enough: a fake staff login page under the real
hostname defeats every control in this build, because the user is voluntarily handing over a
one-time PIN to something the browser says is genuine.

**Response:**

1. Delete the tunnel in Cloudflare. This invalidates the token and drops every connector,
   including mine — the service goes down deliberately, because a down service is better than a
   half-attacker-served one.
2. Create a new tunnel, get a new token, restart the local connector.
3. Because this build uses a **quick tunnel**, the hostname changes; the supervisor republishes
   the new URL to KV and the Pages Function picks it up. In production with a named tunnel, the
   DNS record is repointed instead and the hostname is stable.
4. Check the Cloudflare dashboard's connector list for the tunnel *before* deleting it, if there
   is time — the attacker's connector IP is evidence.
5. Assume anything served during the window was attacker-controlled and notify accordingly.

---

## 4 — Paged: the staff console is down

Five steps, ordered so that **each one eliminates a layer**. The order is the value; running
them in a different order means debugging a healthy component.

1. **Edge — `curl -s https://$ADMIN/cdn-cgi/trace`.** Answered by Cloudflare without touching my
   origin (R4). No response at all → the problem is Cloudflare or DNS, and nothing downstream
   is worth looking at. A 302 to the team domain → Access is enforcing and the edge is *fine*;
   skip to step 5.
2. **Tunnel — is the connector registered and healthy?** `cloudflared`'s local metrics endpoint,
   and the connector list for the tunnel. A dead connector produces a 530/1033 at the edge,
   which looks like an application error and is not one.
3. **Process — is the origin actually listening?** `ss -ltnp | grep 300` and a loopback `curl`
   to the health route. This distinguishes "the tunnel has nothing to talk to" from "the tunnel
   is broken". A crashed Node process and a dead tunnel present almost identically from outside.
4. **Policy — does a known-good identity get in?** Log in as a test identity. If the process is
   healthy and the tunnel is up but a valid user is refused, the fault is in Access: a policy
   edit, an expired application, or a precedence change that put a Block above the wrong Allow
   (R14 in its failure direction).
5. **Token — is the origin rejecting valid tokens?** The origin's own failure code says which
   check failed: `wrong_audience` means an AUD tag drifted after a `terraform apply`;
   `unknown_key` means JWKS is stale or the team domain is wrong; `expired` means clock skew.
   This is the layer that looks like an outage but is a configuration mismatch, and it is last
   because it is only reachable once the four layers above are known good.

The distinction the runbook is built around: steps 1–3 are **infrastructure** (something is not
running), steps 4–5 are **policy and identity** (everything is running and refusing on purpose).
They fail identically from a browser and are fixed completely differently.
