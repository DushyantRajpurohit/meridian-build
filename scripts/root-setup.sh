#!/usr/bin/env bash
# =========================================================================================
# The only part of this build that needs root, in one place, in stages you can stop between.
#
#   sudo bash scripts/root-setup.sh base       # R6 firewall, R8 units, sshd, WARP, R35 address
#   sudo bash scripts/root-setup.sh verify     # prove each of the above, change nothing
#   sudo bash scripts/root-setup.sh harden     # key-based auth, then passwords off
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
#
# The env PATH is not decoration. `runuser -u` drops privileges but does NOT source the
# target user's profile, so the command inherits root's PATH — which under sudo is the
# `secure_path` from /etc/sudoers, and that deliberately excludes ~/.local/bin. terraform
# lives there. Without this line `tf.sh` dies on "terraform: command not found" and every
# read below fails identically to the resource genuinely being absent.
# Resolved through a login shell, and `tail -n1` because a chatty .bashrc will print ahead of
# the answer and the last line is the one `command -v` wrote. Slurping the whole PATH out of
# that shell instead would inherit the same noise as a PATH entry.
TF_DIR="$(runuser -l "${RUN_USER}" -c 'command -v terraform' 2>/dev/null | tail -n1)"
TF_DIR="${TF_DIR:+$(dirname "${TF_DIR}")}"
as_user() { runuser -u "${RUN_USER}" -- env PATH="${TF_DIR:+${TF_DIR}:}${PATH}" "$@"; }

PRIVATE_IP="$(as_user "${REPO}/terraform/tf.sh" output -raw private_host_ip 2>/dev/null || echo '10.99.0.1')"

# ---------------------------------------------------------------------------------------
# base
# ---------------------------------------------------------------------------------------

# Refuse to build a box-side half that cannot work. Installing the connector while the three
# Zero Trust resources are missing produces the worst failure in this build: `ssh 10.99.0.1`
# opens a connection that goes nowhere, WARP calls the address local and puts it on the wifi,
# and Cloudflare never sees the attempt — so there is nothing in any log to read. Better to
# stop here with a sentence than to hand you that.
preflight() {
  local missing=()
  local state
  local rc=0

  # 2>&1 and not 2>/dev/null. An unreadable state and an unapplied account are different
  # problems with opposite fixes, and swallowing stderr renders them identical: an empty
  # string fails all five greps below and reports a fully-applied account as missing
  # everything. If terraform could not speak, say so and stop — do not diagnose.
  state="$(as_user "${REPO}/terraform/tf.sh" state list 2>&1)" || rc=$?
  if [[ ${rc} -ne 0 ]]; then
    echo "root-setup: could not read the terraform state as ${RUN_USER}. That is not the" >&2
    echo "same as the resources being absent, so I am not going to guess which it is." >&2
    echo >&2
    printf '  %s\n' "${state}" >&2
    echo >&2
    echo "Fix that first, then re-run. Sanity check as yourself, not as root:" >&2
    echo "  cd terraform && ./tf.sh state list" >&2
    exit 1
  fi

  grep -q 'cloudflare_zero_trust_tunnel_cloudflared\.private'          <<<"${state}" || missing+=("the named tunnel")
  grep -q 'cloudflare_zero_trust_tunnel_cloudflared_route\.box'        <<<"${state}" || missing+=("the /32 private route")
  grep -q 'cloudflare_zero_trust_device_custom_profile\.operator'      <<<"${state}" || missing+=("the split-tunnel profile (R35 — WARP will treat 10.99.0.1 as local without it)")
  grep -q 'gateway_policy\.private_allow_operator'                     <<<"${state}" || missing+=("the Gateway allow policy (R36)")
  grep -q 'gateway_policy\.private_block_everyone_else'                <<<"${state}" || missing+=("the Gateway block policy (R36 — without it the allow grants nothing)")

  [[ ${#missing[@]} -eq 0 ]] && return 0

  echo "root-setup: the Cloudflare side is incomplete. Missing:" >&2
  printf '  - %s\n' "${missing[@]}" >&2
  cat >&2 <<'MSG'

Apply the Cloudflare side first:  cd terraform && ./tf.sh apply

If that apply fails 403 on exactly these resources, the API token is missing the Zero Trust
scope rather than anything being wrong with the config. Confirm which it is:

  curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $CF_API_TOKEN" \
    https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/gateway/rules

403 there means the scope is missing: add Account -> Zero Trust -> Edit to the existing token
and re-run the apply. Editing a token's permissions keeps its secret value, so .env does not
change — do not go looking for a new one to paste.

MSG
  exit 1
}

stage_base() {
  preflight

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
  # `command -v node` is not good enough here, and the way it fails is quiet. Under runuser it
  # resolved /usr/bin/node — the distro's Node 18 — while nvm's own default alias on this box
  # is 20, and the repo needs 24 (.nvmrc; wrangler requires >= 22). The unit then crash-looped
  # on MODULE_NOT_FOUND, which names no version and reads like a broken install.
  #
  # So: source nvm, ask it for the version .nvmrc actually pins, then check the major version
  # and refuse rather than write a unit that cannot start.
  NODE_BIN="$(as_user bash -lc "
    export NVM_DIR=\"\${NVM_DIR:-\$HOME/.nvm}\"
    [ -s \"\$NVM_DIR/nvm.sh\" ] && . \"\$NVM_DIR/nvm.sh\" >/dev/null 2>&1
    want=\"\$(cat '${REPO}/.nvmrc' 2>/dev/null || echo node)\"
    nvm which \"\$want\" 2>/dev/null || command -v node
  " | tail -n1)"
  [[ -n "${NODE_BIN}" && -x "${NODE_BIN}" ]] || die "no usable node found for ${RUN_USER} (asked nvm for .nvmrc's version, then PATH)"

  NODE_MAJOR="$("${NODE_BIN}" --version 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/')"
  [[ "${NODE_MAJOR}" =~ ^[0-9]+$ ]] || die "could not read a version out of ${NODE_BIN}"
  (( NODE_MAJOR >= 22 )) || die "${NODE_BIN} is Node ${NODE_MAJOR}; this repo needs >= 22 (.nvmrc pins 24). Install it for ${RUN_USER}:  nvm install && nvm use"
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
  note "ufw enabled, default deny incoming, LAN SSH allowed for now"

  head_ "R6/R33 — sshd on the operations address and nowhere else"
  # Ubuntu 24.04 ships sshd under SOCKET ACTIVATION: ssh.socket owns :22 and spawns `sshd -i`
  # per connection. `systemctl start ssh` then raises a SECOND, standalone listener on the same
  # port and the two fight — the socket accepts a connection, triggers a service that is already
  # running, and drops it. The symptom is `Connection closed by <host> port 22` immediately
  # after the password prompt with NOTHING in the journal, because no sshd instance ever owned
  # the connection long enough to log a line. That is not a credentials problem and reads
  # exactly like one.
  #
  # Socket activation also makes `ListenAddress` dead config: the socket unit decides what to
  # bind, not sshd_config. Binding only the operations address is the whole point here, so
  # socket activation has to go rather than be worked around.
  systemctl disable --now ssh.socket >/dev/null 2>&1 || true

  install -d -m 0755 /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/10-meridian.conf <<SSHD
# Written by scripts/root-setup.sh. R6/R33.
#
# The same argument as putting the address on \`lo\`: a /32 on loopback is never ARPed, so a
# listener bound to it does not exist on the LAN at any layer. Turn ufw off entirely and this
# is still unreachable from the wifi, because there is no interface to send a frame to. The
# firewall becomes the second line rather than the only one.
ListenAddress ${PRIVATE_IP}
PermitRootLogin no

# PasswordAuthentication is deliberately left at the distro default (yes) by \`base\`, so that
# a wrong turn here costs a retry rather than the machine. \`harden\` installs a key and turns
# it off, and is a separate stage for exactly that reason.
SSHD

  # sshd cannot bind an address that does not exist yet, so at boot it has to come up after the
  # unit that puts the address on lo. Requires and not Wants: with no operations address there
  # is nothing for sshd to answer on, and failing loudly beats listening nowhere.
  install -d -m 0755 /etc/systemd/system/ssh.service.d
  cat > /etc/systemd/system/ssh.service.d/10-meridian-ops-address.conf <<UNIT
[Unit]
After=meridian-ops-address.service
Requires=meridian-ops-address.service
UNIT

  systemctl daemon-reload
  systemctl enable ssh >/dev/null 2>&1 || true
  systemctl restart ssh
  if ss -tln | grep -qE "^LISTEN.*[^0-9.]${PRIVATE_IP}:22 "; then
    note "sshd listening on ${PRIVATE_IP}:22 only"
  else
    note "WARNING: sshd is not bound to ${PRIVATE_IP}:22 — check: ss -tln | grep :22"
  fi

  echo
  echo "base done. Next:"
  echo "  1. sudo bash scripts/root-setup.sh verify"
  echo "  2. enrol this machine in WARP:  warp-cli registration new && warp-cli connect"
  echo "     (if status says 'Registration Missing ... Does not exist in API', the local"
  echo "      registration points at a device the account no longer has — clear it first:"
  echo "      warp-cli registration delete; then run 'new' again)"
  echo "  3. sudo bash scripts/root-setup.sh harden   # key auth, then passwords off"
  echo "  4. only then:                   sudo bash scripts/root-setup.sh lockdown"
  echo
  echo "  NOTE ON PROVING R33. 'ssh ${RUN_USER}@${PRIVATE_IP}' typed on THIS box goes over"
  echo "  loopback — the address is on lo here, so the kernel answers before WARP is asked."
  echo "  It succeeds with WARP switched off and proves nothing about the tunnel. The"
  echo "  demonstration needs a SECOND device enrolled in the same WARP team."
}

# ---------------------------------------------------------------------------------------
# verify — reads only
# ---------------------------------------------------------------------------------------

stage_verify() {
  head_ "R6 — nothing listening off loopback"
  ss -ltn | awk 'NR==1 || ($4 !~ /^127\.|^\[::1\]/)'
  # Judge the sshd line rather than waving at it. The first version of this stage printed
  # "sshd is expected here", which passed a listener bound to 0.0.0.0 — every interface,
  # including the wifi — as if it were the intended state. A check that accepts the thing it
  # exists to catch is decoration.
  if ss -ltn | grep -qE '^LISTEN.*(0\.0\.0\.0|\*|\[::\]):22 '; then
    echo "  FINDING: sshd is bound to every interface, not just ${PRIVATE_IP}."
    echo "           ufw is then the only thing keeping it off the LAN. Re-run: base"
  elif ss -ltn | grep -qE "[^0-9.]${PRIVATE_IP}:22 "; then
    echo "  sshd is bound to ${PRIVATE_IP}:22 only — not present on the LAN at any layer"
  else
    echo "  FINDING: nothing is listening on ${PRIVATE_IP}:22 — R33 has no destination"
  fi
  echo "  (anything else above is a finding)"

  head_ "R33 — how this box itself routes to the operations address"
  # The trap this section is most likely to hide. 10.99.0.1 is assigned to lo ON THIS BOX, so
  # the kernel's `local` table answers for it before any WARP route is consulted. `ssh
  # dushyant@10.99.0.1` typed here therefore never leaves the machine and proves NOTHING about
  # the tunnel — it succeeds identically with WARP off, disconnected, or uninstalled.
  ip route get "${PRIVATE_IP}" 2>&1 | head -1 | sed 's/^/  /'
  if ip route get "${PRIVATE_IP}" 2>/dev/null | head -1 | grep -q '^local '; then
    echo "  NOTE: that says 'local' — from this box the address is loopback, not the tunnel."
    echo "        R33 can only be demonstrated from a SECOND device enrolled in WARP."
  fi

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


# ---------------------------------------------------------------------------------------
# harden — key-based auth. Separate from base because it is the stage that can lock you out.
# ---------------------------------------------------------------------------------------

stage_harden() {
  local home key
  home="$(getent passwd "${RUN_USER}" | cut -d: -f6)"
  key="${home}/.ssh/id_ed25519"

  head_ "R33 — a key for ${RUN_USER}"
  if [[ -f "${key}" ]]; then
    note "keypair already present at ${key}"
  else
    # Generated AS the user, so the private key is theirs and root never owns it. No
    # passphrase: this key's job is to replace a password on a port that is already gated by
    # WARP enrolment and a Gateway identity rule, and a passphrase-protected key the operator
    # cannot use under pressure gets replaced by a password rule the day of the first incident.
    # The tradeoff is stated here rather than left to be discovered in the file mode.
    as_user ssh-keygen -t ed25519 -N '' -C "${RUN_USER}@meridian-ops" -f "${key}" >/dev/null
    note "keypair generated at ${key}"
  fi

  as_user install -d -m 0700 "${home}/.ssh"
  as_user touch "${home}/.ssh/authorized_keys"
  as_user chmod 0600 "${home}/.ssh/authorized_keys"
  if as_user grep -qFf "${key}.pub" "${home}/.ssh/authorized_keys" 2>/dev/null; then
    note "public key already authorised"
  else
    as_user bash -c "cat '${key}.pub' >> '${home}/.ssh/authorized_keys'"
    note "public key authorised"
  fi

  head_ "R33 — prove the key works BEFORE removing the password"
  # The order matters and is the entire reason this is its own stage. Turn passwords off first
  # and then discover the key is not accepted, and the only way back in is the console.
  if as_user ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
       -o ConnectTimeout=5 "${RUN_USER}@${PRIVATE_IP}" true 2>/dev/null; then
    note "key authentication succeeded"
  else
    die "key authentication did NOT succeed — leaving password auth on. Debug with:
       ssh -v ${RUN_USER}@${PRIVATE_IP}
     and re-run this stage once it works."
  fi

  head_ "R6 — passwords off"
  cat > /etc/ssh/sshd_config.d/20-meridian-keys-only.conf <<'SSHD'
# Written by scripts/root-setup.sh harden, and only after a key login was observed to work.
PasswordAuthentication no
KbdInteractiveAuthentication no
SSHD
  systemctl restart ssh
  note "password authentication disabled"

  if as_user ssh -o BatchMode=yes -o ConnectTimeout=5 "${RUN_USER}@${PRIVATE_IP}" true 2>/dev/null; then
    note "still reachable by key after the restart"
  else
    # Put it back rather than leave the operator locked out on the strength of a config file.
    rm -f /etc/ssh/sshd_config.d/20-meridian-keys-only.conf
    systemctl restart ssh
    die "key login broke when passwords were removed — reverted, password auth is back on"
  fi
}

case "${STAGE}" in
  base)     stage_base ;;
  verify)   stage_verify ;;
  harden)   stage_harden ;;
  lockdown) stage_lockdown ;;
  *) die "usage: sudo bash scripts/root-setup.sh {base|verify|harden|lockdown}" ;;
esac
