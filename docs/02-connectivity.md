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
rule is such a rule before it will run.

Verified rather than asserted (GR5), with `cloudflared 2026.8.2` and the table above, once with
the catch-all and once with the last line deleted:

```
$ cloudflared tunnel --config good.yml ingress validate
Validating rules from good.yml
OK
$ echo $?
0

$ cloudflared tunnel --config bad.yml ingress validate
Validating rules from bad.yml
Validation failed: The last ingress rule must match all URLs (i.e. it should not have a
hostname or path filter)
$ echo $?
1
```

The non-zero exit is the whole point: `cloudflared tunnel run` performs the same validation at
startup, so a table without a catch-all does not start a connector that then 404s — it fails to
start a connector at all.

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

## R8 — two ways a unit file looks configured and is not

Both units were written, installed, enabled and reported `active` by `verify` while carrying a
defect that only showed up under a condition the unit exists to survive. Both are recorded
here because the *shape* of each mistake generalises: a setting that is silently ignored, and
an interpreter resolved by the wrong question.

### `StartLimitIntervalSec` in `[Service]`

```
systemd[1]: /etc/systemd/system/cloudflared-private.service:32:
            Unknown key name 'StartLimitIntervalSec' in section 'Service', ignoring.
```

The start rate limiter lives in `[Unit]`. Put it in `[Service]` and systemd ignores it, logs
that one line, and carries on with the default: five starts in ten seconds, after which the
unit is marked `failed` and **systemd stops restarting it**. `Restart=always` is still in the
file, still correct-looking, and no longer true.

The condition that triggers it is precisely the one the setting was added for. A flapping
uplink makes `cloudflared` exit repeatedly; with `RestartSec=5s`, five exits inside ten seconds
is reachable, and the connector then stays down until someone notices — through an outage,
which is when nobody is reading `journalctl` for `Unknown key name`. The comment in the file
explained the reasoning perfectly and sat above a line that did nothing.

Fixed in both units, with `StartLimitBurst=0` alongside it, and the comment moved to the
section that actually reads the setting.

### `command -v node` resolved the wrong Node

`meridian-origins.service` crash-looped on:

```
code: 'MODULE_NOT_FOUND'
Node.js v18.19.1
```

`root-setup.sh` picked the interpreter with `as_user bash -lc 'command -v node'`. Under
`runuser` that returned `/usr/bin/node` — the distro's Node 18 — even though nvm's default
alias for this user is 20 and `.nvmrc` pins **24**. Three different answers to "where is node",
and the question as asked chose the worst one.

The error names no version. `MODULE_NOT_FOUND` reads as a broken `node_modules`, and the
obvious next move — reinstall dependencies — is wrong and costs time. The version line is the
only clue, and it is the last line of a stack trace.

Fixed by asking a better question: source `nvm`, resolve the version `.nvmrc` names, then
**assert the major version is at least 22** and refuse to write the unit otherwise. A unit that
cannot start is worse than a stage that stops, because the stage tells you why.

### A space in the repository path

The Node 24 fix landed and the unit still crash-looped, now with a better error:

```
Error: Cannot find module '/home/dushyant/Documents/Ayush'
Node.js v24.19.0
```

This repository lives under `~/Documents/Ayush HealthCare/…`. systemd splits `ExecStart=` on
whitespace, so the substituted repo path became **two arguments** and `node` was handed
`/home/dushyant/Documents/Ayush` as the script to run. `WorkingDirectory=` was unaffected —
it is a single-value setting and takes the rest of the line — which is why the unit started at
all and failed one layer further in.

Fixed by quoting both substituted paths in `ExecStart`, which is systemd's documented answer
and does not depend on `WorkingDirectory` staying where it is.

Two things generalise. **The truncated path is the whole diagnosis** and it is easy to skim
past: `MODULE_NOT_FOUND` on a path that is a *prefix* of the real one is a quoting bug every
time, in systemd units, shell scripts and `Dockerfile` `CMD` alike. And **`Restart=always`
converts a crash into a silence** — the unit never reaches `failed`, so it sits in
`activating (auto-restart)` indefinitely and every status check reports a word that is not
"failed". `verify` now treats anything other than `active` as a finding, prints the last error
lines from the journal, and separately flags a unit whose `NRestarts` has climbed, because a
unit that is `active` on its 206th attempt is not healthy either.

### `.bin/tsx` is a shell script

With the path quoted, node received it intact and failed differently:

```
node_modules/.bin/tsx:2
basedir=$(dirname "$(echo "$0" | sed -e 's,\\,/,g')")
SyntaxError: missing ) after argument list
```

`node_modules/.bin/<name>` is npm's shim: a `/bin/sh` script that locates node and re-execs the
real entrypoint. Handing it to `node` makes node parse shell as JavaScript. The error names the
right file and the right line and still misleads, because `SyntaxError` in `node_modules` reads
as a corrupt dependency rather than as the wrong kind of file.

Running the shim *directly* — `ExecStart=…/node_modules/.bin/tsx …` — is the tempting fix and
would work when tested in a terminal, then fail as a unit: the shim needs `node` on `PATH`, and
systemd hands a unit a minimal `PATH` with no nvm in it. The fix that works in both places is to
name the real entrypoint, `node_modules/tsx/dist/cli.mjs`, which is what the package's own
`bin` field points at.

### The check that aborted at the thing it was checking for

The `verify` rewrite above introduced its own bug in one line:

```bash
st="$(systemctl is-active "$u" 2>&1)"
```

`systemctl is-active` **exits 3** for `activating`. Under `set -euo pipefail`, a standalone
assignment whose command substitution fails takes the exit status of that substitution, so the
whole stage terminated at the first unhealthy unit — printing the healthy connector, then
nothing. Silent, and indistinguishable from the output simply ending.

The version it replaced was accidentally immune: the substitutions were arguments to `printf`,
where their exit status is discarded. Making the check *better* is what exposed it to `set -e`
for the first time. Both assignments now end in `|| true`, and the loop is tested against a
genuinely failing unit rather than only against healthy ones — which is the actual lesson, since
every earlier run of this stage had three healthy units and could not have caught it.

## R10 — two connectors on one tunnel, once there was a tunnel to put them on

This was listed as unavailable for most of the build, and the reason was correct at the time: a
**quick** tunnel has no credentials file and no stable name, so a second `cloudflared` process
is a second *tunnel* with a second random hostname, not a second connector on the same one.
Nothing about that is a failover exercise.

§7 changed the premise. Building the private network required a **named** tunnel
(`meridian-private`), which has exactly what a quick tunnel lacks: a stable identity and a
credentials token that more than one process may present. So R10 became available as a
side-effect of a different requirement, and the honest thing was to do it rather than keep
citing the old constraint.

`cloudflared-private.service` is now `cloudflared-private@.service`, a systemd **template**,
instantiated as `@1` and `@2`. Both read the same `/etc/cloudflared/config.yml` and the same
`TUNNEL_TOKEN`, and register independently with the edge.

**The one thing that is not shared is the metrics port.** Two processes cannot bind one, and
the failure is misleading: the second instance exits at startup complaining about an address
already in use, which reads as a tunnel or credentials problem when it is an observability
one. `metrics:` came out of the shared config file and the unit passes
`--metrics 127.0.0.1:2024%i`, so `@1` gets 20241 and `@2` gets 20242.

That also makes the proof local and token-free. Each connector's own endpoint reports the edge
connections **it** holds:

```
$ curl -s 127.0.0.1:20241/metrics | grep ha_connections
cloudflared_tunnel_ha_connections 4
```

Two processes each holding their own set is failover. One process holding eight is not, and a
check that only counted connections at the account would not tell them apart. `verify` reads
both ports and says which. The failover test is then one command —
`systemctl stop cloudflared-private@1` — with `@2` carrying the tunnel.

## R8 — the applications, which were the half still started by hand

The connector and the tunnel supervisor were managed services while the three surfaces they
carry traffic *to* were still `pnpm start` in a terminal. That is the wrong half to automate.
A reboot would have restored a healthy tunnel pointing at nothing — and that is worse than
restoring nothing at all, because every layer reports success and the only complaint comes
from the innermost one, as a 502 with no owner.

`meridian-apps.service` closes it. One unit, because `src/index.ts` binds all three ports in
one process; splitting them so the staff console can restart without the booking page noticing
is worth having and is a change to `src/`, not to a unit file.

It repeats the two lessons the other units paid for: quoted paths in `ExecStart`, because this
repository lives under a directory with a space in it, and `tsx/dist/cli.mjs` rather than
`node_modules/.bin/tsx`, which is a shell shim.
