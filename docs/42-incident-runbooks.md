# R42 — Four procedures, performed and timed

Each runbook is written before it is executed, then executed against the live system with a
wall clock, and the **measured** time recorded honestly — including the time spent on the wrong
step. The times below are recorded on execution; unfilled rows are not yet run and say so.

| # | Procedure | Target | Measured |
|---|---|---|---|
| 1 | Staff member leaves — revoke and terminate live session | — | _blocked: needs `terraform apply`_ |
| 2 | Service token in a public paste — rotate | **< 60s** partner downtime | _blocked: needs `terraform apply`_ |
| 3 | Tunnel token leaks — assess and respond | — | n/a on this path — a quick tunnel has no token |
| 4 | Staff console down — five-step triage | — | **diagnose 3s, recover 14s, total 17s** |
| 5 | *Unplanned:* the quick tunnels died on their own | — | **diagnose ~90s, recover 53s** |

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

### Performed, with a clock

Fault injected deliberately: the origin process killed while the tunnels and the edge stayed up.

```
t+0s   paged
step 1  EDGE     colo=BOM http=http/2 loc=IN tls=TLSv1.3   -> edge fine, fault is downstream
step 2  TUNNEL   4 cloudflared processes alive             -> not the tunnel
step 3  PROCESS  no listener on 3000-3002                  -> FAULT FOUND
t+3s   diagnosed
t+14s  public page back to 200
```

**Diagnosed in 3 seconds, recovered in 14, total 17.** Steps 4 and 5 were never reached, which
is the runbook working: the fault was infrastructure, and the ordering meant I never opened a
policy page or read a token error.

Two honest observations from actually doing it rather than writing it:

**The number is small because the fault was.** I killed a process on a box I was already logged
into. A real page at 3am — a tunnel that died on a machine that had rebooted, or a policy
someone edited yesterday — is bounded by access and by knowing where to look, not by these three
commands. What the drill genuinely establishes is the *ordering*: each step eliminated a layer,
and no step required the one after it.

**What the user saw during the outage was a Cloudflare 502 HTML page, not my Function's JSON
error.** With no origin URL in KV at all, the Function returns its own
`{"error":"bad_gateway"}`. With a URL whose origin is dead, `cloudflared` fails the connection
and Cloudflare's own error page is passed through. Those are two different failures that look
alike to a user and are distinguished by whether the body is JSON — worth knowing before
debugging the wrong layer.

---

## 5 — The one I did not schedule

This was not a drill. Checking the live URLs before submission, the canonical hostname returned
**530** while `staff.` and `api.` still returned their expected 302 and 403 — because those two
are refused by Access at the edge and never reach the origin path at all. Only the public
hostname actually exercises the tunnel, so only it could show the fault.

The runbook found it in the order it is written in:

```
step 1  EDGE      302/403 on the Access-bound hosts        -> edge fine
step 3  PROCESS   127.0.0.1:3000/3001/3002 all answer 403  -> origin alive and refusing correctly
step 2  TUNNEL    curl <quick-tunnel-url>  ->  000         -> FAULT: the hostnames no longer resolve
```

The three `cloudflared` processes were **still running**. That is the detail worth keeping: a
live connector process is not a live tunnel. The quick tunnel hostnames had been reaped at
Cloudflare's end, so the processes were holding connections for names that no longer existed,
and nothing on the box reported an error. `curl` returning `000` rather than an HTTP status is
the tell — that is DNS failing, not an origin refusing.

Recovery: kill the supervisor and its connectors by PID (from `pgrep`, not `pkill -f`, which
matches the killing shell's own command line), restart it, and let it republish three new URLs
into KV. **53 seconds**, most of it waiting for three connectors to register. Diagnosis was the
slower half at roughly ninety seconds, because I began by disbelieving the 530.

### Two bugs the incident exposed, both now fixed

**The supervisor could not see this failure at all.** `scripts/publish-origins.ts` restarted a
tunnel when the `cloudflared` process *exited*. Here the process never exited — it held
connections for a hostname that had stopped resolving. A supervisor watching for process death
is blind to a service that is dead while running. It now probes the hostname it published every
60 seconds and rebuilds the connector after two consecutive failures. The probe treats **any
HTTP status as healthy, including 403**: the origin refusing an unsigned request (R19) means the
whole path worked, so a status code is the success condition and only a thrown `fetch` — DNS or
connect failing — counts as death.

**And then the fix was itself wrong, which is the part worth reading.** The first probe used a
10-second timeout and never consumed the response bodies. In Node an unread body leaves the
socket checked out of undici's pool, so the next probe against the same host waited on a
connection that never freed and timed out — and the supervisor diagnosed *its own leak* as a
dead tunnel and rebuilt a healthy one. Watching it rotate a hostname that answered `403` in
under a second from `curl` is how I found it. Cancelling the body fixed it, and three probe
rounds then passed with no rotations.

Two guards went in alongside, both because a false positive here is worse than the disease — a
needless rotation costs the Function a cold KV read and the visitor a failed request:

- **Three consecutive failures, not two**, at a 15-second timeout.
- **If every surface fails in the same round, do nothing.** Three independent tunnels do not die
  in the same instant; a mobile hotspot dropping for ten seconds looks exactly like that, and
  rotating all three hostnames in response would manufacture the outage the probe exists to
  prevent. A total failure is logged and waited out; only a partial one is acted on.

**The Pages Function turned a rotation into a permanent outage per isolate.** This one is worse,
and I only found it because the canonical hostname alternated between 200 and 530 after the
restart depending on which isolate answered. The Function caches the origin URL per isolate and
drops that cache when the origin stops answering — except a dead quick tunnel **does not throw**
inside a Worker. Cloudflare answers the subrequest itself with 530 (error 1033), so `fetch`
resolves normally, the retry path never ran, and the isolate returned that 530 to visitors for
the rest of its life. The Function now treats a 530 as unreachable, which is safe because the
origin cannot produce one: 530 is an edge status, and every refusal this origin makes is a
401/403 with a reason code.

The first request after a rotation can still fail — KV reads are edge-cached, so the retry may
re-read the stale URL — and then it settles. Ten consecutive 200s after the fix, from a hostname
that was alternating before it.

**And I made the mistake I had already written down.** Cleaning up, I ran
`pgrep -f "publish-origins.ts"` and killed the results, which included the shell running the
command, because its own command line contained the pattern. Exit 144, second time this build.
Writing a warning into a runbook does not install it in your hands.

**What this actually proves, and it is the point of R8.** A quick tunnel is not a deployment.
Nothing here crashed, nothing was misconfigured, and the system still went dark on its own
schedule while I was not looking. A named tunnel under systemd has a stable hostname and
`Restart=always`; this has neither, and the ledger in the README says so. This incident is the
evidence for that claim rather than an embarrassment to be tidied out of it.
