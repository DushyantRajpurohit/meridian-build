#!/usr/bin/env bash
# =========================================================================================
# The only part of this build that needs root, in one place, in stages you can stop between.
#
#   sudo bash scripts/root-setup.sh base       # R6 firewall, R8 units, sshd, WARP, R35 address
#   sudo bash scripts/root-setup.sh verify     # prove each of the above, change nothing
#   sudo bash scripts/root-setup.sh lockdown   # R34 ONLY — deletes the LAN SSH rule, reboots
#
# Every stage is idempotent: running it twice is a no-op, not a second copy. Nothing here
# prints a secret. The connector token is read from `terraform output` as the invoking user
# and written straight to a 0600 file owned by root — it never appears in a command line, in
# this script's output, or in root's shell history (R9).
#
# READ BEFORE `lockdown`. That stage removes the last LAN route into this machine and reboots
# it. The fallback if the Cloudflare path does not come back is the physical console —
# this box's own keyboard — which is the honest answer for a laptop and would not be the
# honest answer for a rack in another building. R34 asks you to document the fallback you had
# in place before attempting it, and that is it.
# =========================================================================================
set -euo pipefail

STAGE="${1:-}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_USER="${SUDO_USER:-}"

# ---------------------------------------------------------------------------------------

die()  { echo "root-setup: $*" >&2; exit 1; }
note() { echo "  $*"; }
head_() { echo; echo "== $* =="; }

[[ "${EUID}" -eq 0 ]] || die "run with sudo"
[[ -n "${RUN_USER}" ]] || die "run via sudo from your normal login, not as a root shell — I need to know whose repo and whose .env to read"

# Run something as the invoking user. Used for every read of the repo, so root never has to
# be trusted with — or blamed for — the contents of .env and terraform.tfstate.
as_user() { runuser -u "${RUN_USER}" -- "$@"; }

PRIVATE_IP="$(as_user "${REPO}/terraform/tf.sh" output -raw private_host_ip 2>/dev/null || echo '10.99.0.1')"

# ---------------------------------------------------------------------------------------
# base
# ---------------------------------------------------------------------------------------

stage_base() {
  head_ "packages"
  # openssh-server: R33/R34 need something to reach. warp: R35's client path.
  export DEBIAN_FRONTEND=noninteractive
  if ! dpkg -s openssh-server >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq openssh-server
    note "openssh-server installed"
  else
    note "openssh-server already present"
  fi

  if ! dpkg -s cloudflare-warp >/dev/null 2>&1; then
    # Pop!_OS 24.04 is noble-based; Cloudflare publishes a noble suite.
    install -d -m 0755 /usr/share/keyrings
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
      | gpg --dearmor --yes -o /usr/share/keyrings/cloudflare-warp.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp.gpg] https://pkg.cloudflareclient.com/ noble main" \
      > /etc/apt/sources.list.d/cloudflare-client.list
    apt-get update -qq
    apt-get install -y -qq cloudflare-warp
    note "cloudflare-warp installed"
  else
    note "cloudflare-warp already present"
  fi

  head_ "R35 — the operations address"
  # On `lo`, not on a physical interface. A /32 on loopback is never ARPed, so it does not
  # exist on the LAN at any layer: an attacker on the same wifi cannot reach it even with the
  # firewall off, because there is nothing to send a frame to. The tunnel reaches it because
  # the connector runs ON this box and talks to it over loopback.
  if ip -4 addr show dev lo | grep -q "inet ${PRIVATE_IP}/32"; then
    note "${PRIVATE_IP}/32 already on lo"
  else
    ip addr add "${PRIVATE_IP}/32" dev lo
    note "${PRIVATE_IP}/32 added to lo"
  fi
  # Persist it. systemd-networkd is not managing lo here, so a tiny unit is the honest way to
  # make it survive the reboot R34 is about to demand.
  cat > /etc/systemd/system/meridian-ops-address.service <<UNIT
[Unit]
Description=Meridian operations address on loopback (R35)
After=network-pre.target
Before=cloudflared-private.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip addr replace ${PRIVATE_IP}/32 dev lo
ExecStop=/sbin/ip addr del ${PRIVATE_IP}/32 dev lo

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now meridian-ops-address.service >/dev/null 2>&1
  note "meridian-ops-address.service enabled"

  head_ "R8 — the private connector as a managed service"
  id -u cloudflared >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin cloudflared
  install -d -m 0755 /etc/cloudflared

  # The binary the unit runs. The user-local copy is fine for a terminal and wrong for a
  # service: a unit must not depend on a path inside somebody's home directory.
  SRC_BIN="$(as_user bash -lc 'command -v cloudflared' 2>/dev/null || true)"
  [[ -n "${SRC_BIN}" ]] || die "cloudflared not found on ${RUN_USER}'s PATH"
  install -o root -g root -m 0755 "${SRC_BIN}" /usr/local/bin/cloudflared
  note "cloudflared -> /usr/local/bin ($(/usr/local/bin/cloudflared --version 2>&1 | head -1))"

  TUNNEL_ID="$(as_user "${REPO}/terraform/tf.sh" output -raw private_tunnel_id)" \
    || die "no private_tunnel_id output — run 'terraform apply' first"

  sed "s|TUNNEL_ID_PLACEHOLDER|${TUNNEL_ID}|" "${REPO}/deploy/cloudflared-private.yml" \
    > /etc/cloudflared/config.yml
  chmod 0644 /etc/cloudflared/config.yml
  note "ingress table -> /etc/cloudflared/config.yml (tunnel ${TUNNEL_ID:0:8}…)"

  # R9 — the token, from terraform output straight into a 0600 file. Written with umask 077 so
  # it is never briefly world-readable between creation and chmod.
  ( umask 077
    { printf 'TUNNEL_TOKEN='
      as_user "${REPO}/terraform/tf.sh" output -raw private_tunnel_token
      printf '\n'
    } > /etc/cloudflared/private.env
  )
  chown root:root /etc/cloudflared/private.env
  chmod 0600 /etc/cloudflared/private.env
  note "connector token -> /etc/cloudflared/private.env (0600, $(wc -c < /etc/cloudflared/private.env) bytes)"

  install -o root -g root -m 0644 "${REPO}/deploy/cloudflared-private.service" \
    /etc/systemd/system/cloudflared-private.service

  head_ "R8 — the quick-tunnel supervisor as a managed service"
  NODE_BIN="$(as_user bash -lc 'command -v node')" || die "node not found on ${RUN_USER}'s PATH"
  sed -e "s|__USER__|${RUN_USER}|g" -e "s|__REPO__|${REPO}|g" -e "s|__NODE__|${NODE_BIN}|g" \
    "${REPO}/deploy/meridian-origins.service" > /etc/systemd/system/meridian-origins.service
  chmod 0644 /etc/systemd/system/meridian-origins.service
  note "meridian-origins.service written (node ${NODE_BIN})"

  # Any hand-started supervisor has to go first, or the unit's copy loses the lock and exits 3
  # — which is the lock doing its job, and would read as a broken unit.
  pkill -u "${RUN_USER}" -f 'publish-origins\.ts' 2>/dev/null || true
  sleep 2
  rm -f /tmp/meridian-publish-origins.lock

  systemctl daemon-reload
  systemctl enable --now cloudflared-private.service
  systemctl enable --now meridian-origins.service
  note "both units enabled and started"

  head_ "R6 — default-deny inbound"
  ufw --force default deny incoming  >/dev/null
  ufw --force default allow outgoing >/dev/null
  # The LAN SSH allow is the "before" state R34 asks you to remove later. It is added here
  # deliberately so that its deletion is a real change to a real control, rather than a
  # ceremony over a rule that never existed.
  ufw allow from 192.168.0.0/16 to any port 22 proto tcp comment 'R34 — the LAN SSH rule, to be deleted' >/dev/null
  ufw allow from 10.0.0.0/8     to any port 22 proto tcp comment 'R34 — the LAN SSH rule, to be deleted' >/dev/null
  ufw --force enable >/dev/null
  systemctl enable ssh >/dev/null 2>&1 || systemctl enable sshd >/dev/null 2>&1 || true
  systemctl start  ssh 2>/dev/null || systemctl start sshd 2>/dev/null || true
  note "ufw enabled, default deny incoming, LAN SSH allowed for now"

  echo
  echo "base done. Next:"
  echo "  1. sudo bash scripts/root-setup.sh verify"
  echo "  2. enrol this machine in WARP:  warp-cli registration new && warp-cli connect"
  echo "  3. prove the private path:      ssh ${RUN_USER}@${PRIVATE_IP}"
  echo "  4. only then:                   sudo bash scripts/root-setup.sh lockdown"
}

# ---------------------------------------------------------------------------------------
# verify — reads only
# ---------------------------------------------------------------------------------------

stage_verify() {
  head_ "R6 — nothing listening off loopback"
  ss -ltn | awk 'NR==1 || ($4 !~ /^127\.|^\[::1\]/)'
  echo "  (the operations address and sshd are expected here; anything else is a finding)"

  head_ "R6 — firewall"
  ufw status verbose | head -8

  head_ "R8 — units"
  for u in cloudflared-private meridian-origins meridian-ops-address; do
    printf '  %-24s enabled=%-8s active=%s\n' "$u" \
      "$(systemctl is-enabled "$u" 2>&1)" "$(systemctl is-active "$u" 2>&1)"
  done

  head_ "R35 — the operations address"
  ip -4 addr show dev lo | grep -E "inet ${PRIVATE_IP}" || echo "  MISSING"

  head_ "R9 — token hygiene"
  stat -c '  %n %a %U:%G' /etc/cloudflared/private.env
  if ps -eo args | grep -v grep | grep -q -- '--token'; then
    echo "  FINDING: a token is on a command line and visible in ps"
  else
    echo "  no token on any command line"
  fi

  head_ "connector"
  systemctl status cloudflared-private --no-pager -n 6 2>&1 | tail -8
}

# ---------------------------------------------------------------------------------------
# lockdown — R34. Destructive on purpose.
# ---------------------------------------------------------------------------------------

stage_lockdown() {
  echo
  echo "R34: this deletes the last LAN SSH allow rule and reboots."
  echo "After the reboot the only route in is Cloudflare — WARP to ${PRIVATE_IP} — plus this"
  echo "machine's physical console, which is the fallback and the reason this is safe to try."
  echo
  echo "Do NOT run this until 'ssh ${RUN_USER}@${PRIVATE_IP}' has worked over WARP at least once."
  echo
  read -r -p "Type LOCKDOWN to proceed: " confirm
  [[ "${confirm}" == "LOCKDOWN" ]] || die "not confirmed, nothing changed"

  # Delete by rule text rather than by number: ufw renumbers on every delete, so deleting
  # "rule 3" twice deletes two different rules.
  while ufw status numbered | grep -q 'R34'; do
    N="$(ufw status numbered | grep -m1 'R34' | sed 's/^\[ *\([0-9]*\).*/\1/')"
    ufw --force delete "${N}" >/dev/null
  done
  note "LAN SSH rules deleted"
  ufw status verbose | head -8

  echo
  echo "rebooting in 10s — regain access with: warp-cli connect && ssh ${RUN_USER}@${PRIVATE_IP}"
  sleep 10
  systemctl reboot
}

case "${STAGE}" in
  base)     stage_base ;;
  verify)   stage_verify ;;
  lockdown) stage_lockdown ;;
  *) die "usage: sudo bash scripts/root-setup.sh {base|verify|lockdown}" ;;
esac
