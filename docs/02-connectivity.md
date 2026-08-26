# §2 — Connectivity

R6 and R8 are properties of the live box and are verified there. R10 is not achievable on this
path and says why. R7, R9 and R11 are explanations, and they are the point of the section.

---

## R6 — Outbound only, default-deny inbound

Two separate claims, and they need separate evidence.

**Nothing is listening.** Current state of this box:

```
$ ss -ltn | awk 'NR==1 || $4 !~ /^127\.|^\[::1\]/'
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process
```

One header row and no rows under it: there is no TCP listener on any non-loopback interface.
The three application surfaces bind `127.0.0.1:3000/3001/3002` explicitly (R7's trap — the
default in most frameworks is `0.0.0.0`, and the difference is the entire assignment).

**The firewall is default-deny inbound.** `ufw default deny incoming`, verified with
`ufw status verbose`. This is belt and braces given the line above: with no listener there is
nothing to reach, but the firewall is what holds if a future process binds carelessly. One is a
property, the other is a control; I want both.

**Nothing inbound is possible in the first place.** The box is on a mobile hotspot behind
CGNAT. There is no public address and no port forward, so `nmap -Pn -p- $BOX_IP` from outside
cannot reach the machine at all — and I want to be precise about what that proves, because it
is easy to overclaim. That scan proves *unreachability from the internet*, which is partly a
property of the network I happen to be on and not solely of my configuration. The scan that
proves my own work is the one run from another host on the same LAN, because that is the
attacker who is past CGNAT. Both belong in the recording; only the second is evidence about me.

**Why `cloudflared` does not contradict any of this.** It makes an outbound QUIC/HTTPS
connection to Cloudflare and keeps it open. Requests arrive as responses on a connection this
box originated. There is no accept() anywhere in the path, which is why this survives being
behind CGNAT — and why "zero inbound" is a description of the architecture rather than a
firewall rule that someone can later disable.

---

## R7 — The ingress table, and what happens when the catch-all is missing

The table routes by hostname to a **loopback** port, and ends in a catch-all:

```yaml
ingress:
  - hostname: staff.example.com
    service: http://127.0.0.1:3000
  - hostname: api.example.com
    service: http://127.0.0.1:3001
  - hostname: clinic.example.com
    service: http://127.0.0.1:3002
  - service: http_status:404          # the catch-all
```

**What `cloudflared` does when the catch-all is missing: it refuses to start.**

This is the answer, and it surprises people who expect a runtime 404. The final rule is not a
default that `cloudflared` falls back on — it is a *validation requirement*. A rule with no
`hostname` and no `path` is what makes the table total, and `cloudflared` checks that the last
rule is such a rule before it will run. Without it you get
`ingress: The last ingress rule must match all URLs (i.e. it should not have a hostname or path
filter)` and the process exits non-zero. `cloudflared tunnel ingress validate` reports the same
thing without starting anything.

**Why it is designed that way, which is the more interesting half.** An ingress table is
evaluated top to bottom and stops at the first match, exactly like the Access policies in R14.
A partial table has undefined behaviour for unmatched requests, and there are only two things
`cloudflared` could do: guess a default, or refuse. Guessing a default is how you end up with an
unmatched hostname silently reaching the first rule's service — that is, a hostname you never
configured being served by your staff console. So the tool makes totality a startup condition
rather than a runtime accident.

The operational consequence is worth stating because it is counter-intuitive in the good
direction: **this failure is loud and immediate.** A missing catch-all takes the service down at
start rather than misrouting one hostname quietly at 3am. That is the right trade, and it is the
opposite of the R14 failure mode, where a misordered policy list is silently accepted and simply
stops enforcing.

`http_status:404` is the right terminal rather than proxying to an app, because an unmatched
hostname should be told nothing about what exists behind the tunnel.

**On this path**, a quick tunnel has no ingress table at all — it takes a single `--url` and
routes everything to it. The table above is what the named-tunnel deployment uses and what the
supervisor writes; the explanation stands on its own either way, and R39's "full replace" trap
follows directly from it (see the §8 section of the README).

---

## R8 — Managed service, survives reboot

`cloudflared service install` registers a systemd unit with `Restart=always` and
`WantedBy=multi-user.target`, so the connector comes back after a reboot with nobody logged in.
Verified by `systemctl is-enabled cloudflared` and by an actual reboot, not by reading the unit
file.

The distinction that matters: running `cloudflared tunnel run` in a terminal is not a
deployment. It dies with the SSH session, it dies with the terminal, and — the case that
actually bites — it dies on reboot at 4am and nobody notices until the clinic opens.

---

## R9 — Credentials file vs connector token

They are frequently described as interchangeable. They are not, and the difference decides
where each one is allowed to live.

| | Credentials file | Connector token |
|---|---|---|
| Created by | `cloudflared tunnel create` | the dashboard, or `tunnel token` |
| Form | a JSON file on disk (`<UUID>.json`) | a single base64 string |
| Contains | `AccountTag`, `TunnelID`, `TunnelSecret` | the same three values, encoded |
| Used by | locally-managed tunnels | remotely-managed tunnels |
| Secret? | **yes** | **yes** |

**Both are secrets.** The `TunnelSecret` is the tunnel's private key; either artefact lets the
holder register a connector for the tunnel and receive a share of its traffic.

**The token is the more dangerous of the two,** for two reasons that have nothing to do with
cryptography.

*First, it is designed to be pasted.* It is one line, it appears in the dashboard next to a copy
button, and every install guide shows it as a command-line argument. So it ends up in shell
history, in `ps` output while the install runs, in CI job logs, in Dockerfiles, in the
screenshot someone takes of the working command, and in the Slack message to the colleague who
is doing the install. A JSON file with mode 600 is handled like a file; a token is handled like
a string, and strings leak through channels that files do not.

*Second, it grants more.* On a remotely-managed tunnel, the token also lets the holder **fetch
the tunnel's configuration from Cloudflare** — which is to say the ingress table: internal
hostnames, internal IP addresses, and which local ports serve what. The credentials file gives
an attacker the ability to intercept traffic; the token gives them that *plus a map of the
internal network* they have just gained a foothold in. That is a reconnaissance gift the file
does not offer.

**Where each belongs.** The credentials file: on the connector host only, mode 600, owned by the
service user, at a path outside any repository, delivered by configuration management rather
than by hand. The token: in a secret manager, injected into the unit through a systemd
`EnvironmentFile` (also 600) or at install time from the secret store — never as a literal in a
Dockerfile, a compose file, a CI variable that logs its own value, or a command line. Rotation
for both is the same procedure: create a new tunnel, migrate, delete the old one. There is no
way to rotate a tunnel's secret while keeping the tunnel, which is itself an argument for
treating a leak as R42 procedure 3 rather than as a password change.

---

## R10 — Two connectors on one tunnel

**Not available on this path, and I would rather say so than fake it.** A quick tunnel has no
credentials file and no tunnel UUID to point a second connector at, so two connectors cannot
serve one tunnel. This is a genuine cost of the free route, not an oversight.

What the requirement is getting at, and what I would expect to observe: Cloudflare
load-balances across all healthy connectors for a tunnel. Killing one under sustained load
should produce **zero failed requests** for a client already mid-stream on the surviving
connector, and a small number of in-flight requests on the dying connector either completing or
returning 502/1033 depending on whether `cloudflared` shut down gracefully. `SIGTERM` gives a
graceful drain; `SIGKILL` does not, and the difference shows up in the client's status-code
histogram as a handful of 502s. Reporting "it was seamless" without that histogram is exactly
the kind of claim GR5 exists to stop, which is why I am not reporting it.

---

## R11 — Error 1033, error 1016, and an origin 502

Three failures that look identical in a browser and accuse three different hops. This is the
core of R42's triage, so the distinction is worth being exact about.

| | Error 1033 | Error 1016 | Origin 502 |
|---|---|---|---|
| Accuses | **Cloudflare ↔ connector** | **DNS / routing configuration** | **connector ↔ local service** |
| Means | the edge has no healthy connector for this tunnel | Cloudflare cannot resolve where to send the request | the connector reached the ingress target and got nothing usable |
| Origin involved? | no — never contacted | no — never contacted | yes |

**1033 — "Argo Tunnel error".** The request arrived at Cloudflare, Cloudflare identified the
tunnel, and there was no connector registered and healthy to hand it to. The tunnel exists; it
is empty. **Check first:** is `cloudflared` running on the box (`systemctl status`), and does
the tunnel show a live connector in Cloudflare? Nine times out of ten the process died or the
box lost its uplink. Do not look at the application — it was never asked anything.

**1016 — "Origin DNS failure".** Cloudflare could not resolve the origin the DNS record points
at. In a tunnel deployment this almost always means the `CNAME` points to
`<UUID>.cfargotunnel.com` for a UUID that no longer exists — the tunnel was deleted and
recreated, and the DNS record still names the old one. **Check first:** the DNS record itself,
and whether the UUID in it matches a tunnel that currently exists. This is a configuration
error, not an outage, and it is the classic aftermath of R42's tunnel-token rotation: rotating
the tunnel without repointing DNS produces exactly this.

The tell that separates 1033 from 1016 is *whether Cloudflare got as far as looking for a
connector*. 1016 means it never identified a destination; 1033 means it identified one and found
it empty.

**Origin 502.** The tunnel is healthy and the connector tried to serve the request. Either
nothing is listening on the port the ingress rule names, or the local service accepted the
connection and failed. **Check first:** `ss -ltn` for the port, then `curl` the service over
loopback. If loopback works and the tunnel 502s, the ingress rule points at the wrong port —
which is the failure mode of R39's full-replace, where an apply silently rewrites the table.

The one-line summary I would put on the runbook card: **1016 means Cloudflare does not know
where to send it, 1033 means it knows and nobody is there, 502 means someone was there and it
did not work.**
