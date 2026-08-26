# §7 — Operational access without ports (R33–R36)

## What this path can and cannot do, first

R33 names two client paths: a `cloudflared access ssh` ProxyCommand, and browser-rendered SSH.
**Both bind an Access application to a public hostname, and a public hostname needs a zone.**
There is no zone here. So neither of those two clients exists on this build, and I am not going
to describe them as though they do.

The assignment's own no-domain table nominates the replacement — *"private network plus WARP,
with no public hostname in the path at all"* — which is R35. Built that way, §7 becomes:

| Requirement | On a domain | Here |
|---|---|---|
| R33 SSH only through Cloudflare | Access app on `ssh.example.com`, two clients | Private network + WARP; **one** client |
| R34 delete the LAN rule, reboot, regain access | same | same |
| R35 private IP, no public hostname | same | same, and it is the *only* path |
| R36 CIDR scoped to your identity | Gateway network policy | same |

**What is genuinely lost:** browser-rendered SSH, which is the client that needs nothing
installed on the operator's machine. That is a real capability and its absence is a real gap.

**What is genuinely gained,** and I think it is the larger half: there is no public hostname to
find. The ProxyCommand path still resolves a name in public DNS, and an Access application in
front of it is a login page an attacker can reach and study. The private-network path publishes
nothing. An attacker cannot enumerate what does not resolve.

---

## The shape of it

```
operator's device                    Cloudflare                       the box
────────────────                     ──────────                       ───────
warp-cli connect
  │  device enrolment ─────────────► Access app (type=warp)
  │                                  policy: operator_email only
  │
ssh dushyant@10.99.0.1
  │  split tunnel: include 10.99.0.1/32
  ▼
  ══════ WARP ═══════════════════►  Gateway L4 policy
                                     allow  net.dst.ip in {10.99.0.1}
                                            AND identity.email == operator
                                     block  net.dst.ip in {10.99.0.1}
                                       │
                                       ▼
                                     tunnel route 10.99.0.1/32
                                       │
                                       ▼  (outbound QUIC, established by the box)
                                                          cloudflared-private.service
                                                            warp-routing: enabled
                                                              │
                                                              ▼
                                                          10.99.0.1:22 on `lo`
                                                          sshd
```

No `accept()` anywhere in that diagram happens on an address the internet or the LAN can send
to. The box's connection to Cloudflare is outbound and stays open; the operator's traffic
arrives as a response on it.

---

## R35 — the private network route

**The address lives on `lo`.** `ip addr add 10.99.0.1/32 dev lo`, made permanent by
`meridian-ops-address.service`. A /32 on loopback is never ARPed, so it does not exist on the
LAN at any layer: someone on the same wifi cannot reach it *even with the firewall off*,
because there is no frame to send. The connector reaches it because the connector runs on this
box and talks to it over loopback.

**The route is a /32, not a /24.** The requirement's phrasing invites a /24 and I want to say
why that would be worse. A tunnel route is an *authorisation to forward*: everything inside the
CIDR becomes reachable from the connector's own network namespace, which on this box means the
whole LAN if I let it. One address is the honest size of the thing being exposed. Widening it
later is one line and a plan; narrowing it after somebody has come to depend on it is not.

**The line the whole section depends on** is `warp-routing: enabled` in the connector's config.
Without it Cloudflare has the route, the client sends the packet, and the connector silently
declines to forward — the TCP connection opens and then goes nowhere. Nothing logs a reason.
It is the single easiest way to build all of §7 correctly and have none of it work.

---

## The trap that cost me the most reasoning: the split tunnel

WARP ships with a split-tunnel **exclude** list, and that list contains the RFC1918 ranges —
`10.0.0.0/8` among them. `10.99.0.1` is inside `10.0.0.0/8`.

So on a default profile: the client looks at the destination, decides it is local, and puts the
packet on the wifi, where nothing answers. Cloudflare never sees the connection, so there is
nothing in any log to look at. Every piece of configuration is correct and the thing does not
work.

`cloudflare_zero_trust_device_custom_profile.operator` fixes it, in **include** mode rather than
by poking a hole in `exclude`. Include mode carries *only* what is listed, so the machine's
ordinary traffic keeps going out the ordinary way and the WARP session carries exactly one /32 —
a much smaller blast radius, and much easier to reason about when something else on the box
stops working.

It is a **custom** profile, not the account default, for two reasons: `match` scopes it to the
operator's own identity, so enrolling any other device does not silently inherit a route into
the box; and the account's default profile cannot be deleted, so managing it in Terraform would
mean `destroy` tries to remove something the API refuses to remove — breaking the R40 rebuild
that is already measured and passing.

---

## R36 — scoped to an identity, not to the team

Two Gateway L4 policies, and **the second one is the requirement**:

```
precedence 1  allow  net.dst.ip in {10.99.0.1}  AND  identity.email in {operator}
precedence 2  block  net.dst.ip in {10.99.0.1}
```

Enrolment says *who may join the network*. This says *what a joined device may reach*, and the
gap between those two is where the requirement lives. Anyone enrolled in the team can put
`10.99.0.1` in their own split-tunnel include list — that is a client-side setting, and clients
lie. The thing that actually refuses them is this pair, evaluated at Cloudflare, where the
client's opinion does not participate.

**Drop the block rule and the allow rule is decoration.** Gateway's default for unmatched L4
traffic is to pass it, so a policy set that only ever says "allow" grants nothing and denies
nothing — the CIDR is open to every enrolled device and the dashboard shows a green rule
claiming otherwise. It is R14's ordering mistake in a different product: a control that reads
as if it works.

---

## R34 — deleting the last LAN rule

**The fallback, documented before the attempt, because that is what the requirement asks.**
This box is a laptop and I have its keyboard. If the Cloudflare path does not come back after
the reboot, I log in on the physical console and re-add the ufw rule. That is an honest
fallback for a laptop and would be a dishonest one for a machine in a rack in another building
— there the equivalent is a serial console or an out-of-band card, and *not having one* is a
reason not to run this procedure at all.

The order is not negotiable, and `scripts/root-setup.sh lockdown` refuses to run until you have
typed the confirmation:

1. `base` puts the LAN SSH allow rule **in** — so that deleting it later is a real change to a
   real control rather than a ceremony over a rule that never existed.
2. Enrol WARP, connect, and `ssh dushyant@10.99.0.1` **successfully, at least once**.
3. Only then `lockdown`: delete the rule, reboot.
4. Regain access with `warp-cli connect && ssh dushyant@10.99.0.1` and nothing else.

The deletion loops on rule *text*, not on rule number. `ufw` renumbers after every delete, so
deleting "rule 3" twice deletes two different rules — and the second one is whatever happened
to slide into the gap.

---

## What `verify` proves, and what it does not

`sudo bash scripts/root-setup.sh verify` reads and changes nothing. It shows the non-loopback
listeners, the firewall's default policy, all three units' enabled/active state, the operations
address, and the mode and owner of the token file — plus an explicit check that no token is
sitting on any command line where `ps` would show it (R9).

What it cannot prove is R34, because R34 is a claim about a machine that has rebooted. The only
evidence for that is the reboot itself, and it belongs in the recording.

---

## Two drifts the first apply left behind

The apply succeeded and `terraform plan` then reported **2 to change**, every time, forever.
Both were mine, both are the same mistake in two different products, and neither is a security
bug — which is exactly why they are worth writing down.

**Cloudflare names the device-enrolment application itself.** I called it
`Meridian WARP enrolment`; the API stores `Warp Login App` and overwrites what is sent. So the
config asked for one name, the server reported another, and the plan proposed the same
correction on every run.

**Gateway lowercases the identity address.** `Dushyantrajpurohit5412@gmail.com` went in and
`dushyantrajpurohit5412@gmail.com` came back, so the string in the config never equalled the
string in the API. The policy *matched correctly the whole time* — Gateway's own comparison is
case-insensitive — so nothing was ever unprotected. `lower()` in the expression fixes it.

**Why bother, if neither one is a vulnerability.** Because a permanent diff is a broken
instrument. R40's claim is that a rebuild lands on a plan that says *No changes*, and that claim
is only worth something if a plan that says anything else is alarming. Two lines of noise on
every run trains you to read "2 to change" as normal, and the day a real change hides in that
noise you scroll past it. The fix is to make the configuration state what the server will
actually do — the app's real name, the address's real case — and let the comment carry the
meaning the value no longer can.

## The preflight that reported a working account as empty

`root-setup.sh base` opens with a preflight, because the failure it prevents is the worst one
in this build: install the connector while the Zero Trust resources are missing and `ssh
10.99.0.1` opens a connection that goes nowhere, WARP calls the address local and puts it on
the wifi, and Cloudflare never sees the attempt — nothing in any log to read.

The first run of it printed all five resources as missing against an account where all five
were live. Two bugs, one cause:

**`runuser -u` does not source the target user's profile.** It drops privileges and keeps the
environment it was handed, which under `sudo` is the `secure_path` from `/etc/sudoers` — and
that deliberately excludes `~/.local/bin`, which is where `terraform` is installed here. So
`tf.sh` ended at `terraform: command not found`. The two call sites that used `bash -lc` were
unaffected, which is why `cloudflared` and `node` resolved fine and only the state reads broke.

**`2>/dev/null || true` turned that into a diagnosis.** An unreadable state and an unapplied
account are different problems with opposite fixes, and discarding stderr renders them
identical: the empty string fails all five `grep`s and the script confidently names five
resources it never actually looked for. A guard that cannot tell "I could not check" from "I
checked and it is absent" is worse than no guard, because it is believed.

Both fixed: the invoking user's `terraform` directory is resolved once through a login shell
and prepended to the PATH `as_user` hands out, and a non-zero exit from `terraform state list`
now stops with the error terraform actually printed instead of being read as absence.
