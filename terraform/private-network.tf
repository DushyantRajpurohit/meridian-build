# =========================================================================================
# §7 — Operational access without ports (R33–R36), and the named tunnel R8 needs.
#
# R33 names two client paths: a `cloudflared access ssh` ProxyCommand, and browser-rendered
# SSH. Both bind an Access application to a PUBLIC HOSTNAME, and a public hostname needs a
# zone. There is no zone on this path, so neither is available and I am not going to pretend
# otherwise. The assignment's own no-domain table nominates the substitute — "private network
# plus WARP, with no public hostname in the path at all" — which is R35, and it is the
# stronger arrangement rather than a consolation: there is no public hostname left to find,
# enumerate, or attack. What is lost is the browser-rendered client, and that is a real loss,
# because it is the path that needs no software on the operator's machine.
#
# Everything below is created with no zone, no dashboard click, and no `cloudflared tunnel
# login` — that command exists to write a cert.pem authorising a ZONE, which is precisely what
# this account does not have. The API creates named tunnels and private routes without one.
# =========================================================================================

# The named tunnel. Distinct from the three quick tunnels serving the public surfaces: those
# carry HTTP for Pages and rotate their hostnames, this one carries no HTTP at all and exists
# so WARP clients can reach an IP. Splitting them is deliberate — a connector that is also the
# operator's way back into the box should not be restarted every time a web surface flaps.
#
# `tunnel_secret` is left unset so Cloudflare generates it. The alternative is to generate one
# here, which would put a secret I chose into a state file for no benefit; the connector token
# below is derived either way.
# `config_src = "local"` and not "cloudflare", for a reason that is not preference. Private
# network forwarding needs `warp-routing: enabled`, and the provider's remote-config resource
# (v5.24.0) exposes `ingress` and `origin_request` and nothing else — there is no
# `warp_routing` attribute to set. Remote config would therefore mean setting the one line
# that makes this tunnel work in a dashboard, which is exactly the GR4 exception I am not
# willing to take on a security control.
#
# Locally managed puts the ingress table in `deploy/cloudflared-private.yml`, in the repo,
# reviewed in a diff — which is also what R7 actually asks for, and it turns that requirement
# from an explanation into a file.
resource "cloudflare_zero_trust_tunnel_cloudflared" "private" {
  account_id = var.account_id
  name       = "meridian-private"
  config_src = "local"
}

# What the systemd unit authenticates with. Marked sensitive, written to an EnvironmentFile at
# 0600 by scripts/root-setup.sh, and never passed as a command-line argument — R9's whole
# argument about why the token is the more dangerous of the two artefacts is about exactly the
# channels an argument leaks through.
data "cloudflare_zero_trust_tunnel_cloudflared_token" "private" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.private.id
}

# R35 — the private network route. Cloudflare now knows that this CIDR is reachable through
# that tunnel, and WARP clients whose split-tunnel include list carries it will send matching
# packets into Cloudflare rather than onto their local network.
#
# A /32, not the /24 the requirement's phrasing invites. The route is an authorisation to
# forward: everything inside it is reachable from the tunnel's own network namespace, which on
# this box means the whole LAN if I let it. One address is the entire attack surface I need,
# and it is the honest size of the thing being exposed. Widening it later is one line and a
# plan; narrowing it after someone has depended on it is not.
resource "cloudflare_zero_trust_tunnel_cloudflared_route" "box" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.private.id
  network    = var.private_host_cidr
  comment    = "Meridian box, loopback-scoped operations address. SSH only."
}

# ---------------------------------------------------------------------------------------
# Device enrolment — who is allowed to put WARP on a machine and join this network at all
# ---------------------------------------------------------------------------------------

# Without this, enrolment falls back to the account default, and the account default is the
# kind of thing that is permissive because nobody set it. Enrolment is the outer door of the
# private network: a device that cannot enrol cannot reach the CIDR no matter what the Gateway
# policy below says.
resource "cloudflare_zero_trust_access_application" "warp_enrolment" {
  account_id = var.account_id
  name       = "Meridian WARP enrolment"
  type       = "warp"

  policies = [
    {
      id         = cloudflare_zero_trust_access_policy.enrol_operator.id
      precedence = 1
    },
  ]
}

# Scoped to the operator alone, not to `var.staff_emails`. Clinic staff have no business
# holding a route into the box; they use a browser and a URL. This is the same reasoning that
# keeps the partner's service token off the console.
resource "cloudflare_zero_trust_access_policy" "enrol_operator" {
  account_id = var.account_id
  name       = "meridian-enrol-operator"
  decision   = "allow"

  include = [
    { email = { email = var.operator_email } },
  ]
}

# ---------------------------------------------------------------------------------------
# R36 — the network policy. Enrolment says who may join; this says what a joined device
# may reach, and the difference is the requirement.
# ---------------------------------------------------------------------------------------

# Precedence 1: the operator may open TCP to the box's operations address.
#
# The `identity` and `traffic` expressions are ANDed by Gateway, which is what makes this a
# scope rather than a route announcement. Anyone enrolled in the team can *resolve* and *send
# to* 10.99.0.1 — the split tunnel is a client-side setting and clients lie. The thing that
# actually refuses them is this pair of rules, evaluated at Cloudflare, where the client's
# opinion does not participate.
resource "cloudflare_zero_trust_gateway_policy" "private_allow_operator" {
  account_id  = var.account_id
  name        = "meridian-private-allow-operator"
  description = "R36 — the operations address is reachable by one identity, not by the team."
  precedence  = 1
  enabled     = true
  action      = "allow"
  filters     = ["l4"]
  traffic     = "net.dst.ip in {${var.private_host_ip}}"
  identity    = "identity.email in {\"${var.operator_email}\"}"
}

# Precedence 2: everyone else, blocked, explicitly.
#
# This rule is the entire point of the pair and it is the one that is easy to leave out. Drop
# it and the allow above is decoration: Gateway's default for unmatched L4 traffic is to pass
# it, so a policy that only ever says "allow" grants nothing and denies nothing. The same
# mistake as R14's ordering, in a different product — a control that reads as if it works.
resource "cloudflare_zero_trust_gateway_policy" "private_block_everyone_else" {
  account_id  = var.account_id
  name        = "meridian-private-block-everyone-else"
  description = "R36 — without this, the allow above is decoration and the CIDR is open to the team."
  precedence  = 2
  enabled     = true
  action      = "block"
  filters     = ["l4"]
  traffic     = "net.dst.ip in {${var.private_host_ip}}"
}

# ---------------------------------------------------------------------------------------
# The split tunnel. Without this the whole of §7 is built correctly and does not work.
# ---------------------------------------------------------------------------------------

# WARP ships with a split-tunnel EXCLUDE list, and that list contains the RFC1918 ranges —
# including 10.0.0.0/8, which contains the operations address. So on a default profile the
# client looks at 10.99.0.1, decides it is local, and puts the packet on the wifi, where
# nothing answers. Every piece of Cloudflare-side configuration is correct and the connection
# times out. Nothing logs a reason, because from Cloudflare's point of view the request never
# arrived.
#
# A custom profile rather than the default one, for two reasons. It is scoped by `match` to
# the operator's own device, so enrolling anything else does not silently inherit a route into
# the box. And the account's default profile cannot be deleted — managing it here would mean
# `terraform destroy` tries to remove a thing the API refuses to remove, which would break the
# R40 rebuild I have already measured.
#
# `include` mode, not a hole poked in `exclude`: include mode carries ONLY what is listed, so
# this machine's ordinary traffic keeps going out the ordinary way and the WARP session
# carries exactly one /32. Smaller blast radius, and much easier to reason about when
# something on the box stops working.
resource "cloudflare_zero_trust_device_custom_profile" "operator" {
  account_id  = var.account_id
  name        = "meridian-operator"
  description = "R35 — carries the operations address and nothing else."
  match       = "identity.email == \"${var.operator_email}\""
  precedence  = 1
  enabled     = true

  include = [
    {
      address     = var.private_host_cidr
      description = "Meridian operations address"
    },
  ]
}
