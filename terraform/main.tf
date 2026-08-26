# R37 — DNS records are absent here for a reason: the free path has no zone. Everything else
# the requirement names is below, and R39's ingress table has no counterpart because a quick
# tunnel has no ingress table to replace. Both gaps are written up rather than papered over.

provider "cloudflare" {
  # Reads CLOUDFLARE_API_TOKEN from the environment. Never a Global API Key (R38, and an
  # automatic failure if one appears anywhere).
}

# The Function's KV namespace: rate-limit counters, and the quick tunnel URLs the box
# republishes on every boot.
resource "cloudflare_workers_kv_namespace" "meridian" {
  account_id = var.account_id
  title      = "meridian-clinic"
}

resource "cloudflare_pages_project" "clinic" {
  account_id        = var.account_id
  name              = var.pages_project_name
  production_branch = "main"
}

# R25 — the partner lab's credentials. The client secret is created by Cloudflare and is
# available in state, which is exactly why state is gitignored and why R42's rotation drill
# exists.
resource "cloudflare_zero_trust_access_service_token" "partner_lab" {
  account_id = var.account_id
  name       = "partner-lab"
  duration   = "8760h" # one year, and rotated on demand — see R42
}

# ---------------------------------------------------------------------------------------
# Policies. Order is the point; see R14.
# ---------------------------------------------------------------------------------------

# R14 — the Block. It only does anything because it sits ABOVE the Allow in the application's
# policy list. Access evaluates in order and stops at the first match, so a Block underneath
# an Allow that already matched is dead configuration that reads as if it works.
resource "cloudflare_zero_trust_access_policy" "block_former_staff" {
  account_id = var.account_id
  name       = "meridian-block-former-staff"
  decision   = "deny"

  include = [
    for email in var.blocked_emails : { email = { email = email } }
  ]
}

# R13 — the Allow, scoped to the named staff.
resource "cloudflare_zero_trust_access_policy" "allow_staff" {
  account_id = var.account_id
  name       = "meridian-allow-staff"
  decision   = "allow"

  include = [
    for email in var.staff_emails : { email = { email = email } }
  ]
}

# R25 — Service Auth, not Allow. A non_identity decision is what lets a caller with no human
# behind it through, and it is scoped to this one token rather than to any valid service token
# in the account.
resource "cloudflare_zero_trust_access_policy" "partner_service" {
  account_id = var.account_id
  name       = "meridian-partner-service-auth"
  decision   = "non_identity"

  include = [
    { service_token = { token_id = cloudflare_zero_trust_access_service_token.partner_lab.id } }
  ]
}

# ---------------------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------------------

resource "cloudflare_zero_trust_access_application" "admin" {
  account_id       = var.account_id
  name             = "Meridian staff console"
  type             = "self_hosted"
  domain           = var.admin_hostname
  session_duration = var.staff_session_duration

  # R21 — Access will happily set Cf-Access-Authenticated-User-Email on requests to the
  # origin. The origin deletes it on arrival and reads the token instead. Nothing here
  # changes that; it is noted because the convenience is the trap.

  policies = [
    # R14 — precedence 1. Reverse these two numbers and the Block stops working, silently.
    {
      id         = cloudflare_zero_trust_access_policy.block_former_staff.id
      precedence = 1
    },
    {
      id         = cloudflare_zero_trust_access_policy.allow_staff.id
      precedence = 2
    },
  ]
}

resource "cloudflare_zero_trust_access_application" "partner" {
  account_id = var.account_id
  name       = "Meridian partner API"
  type       = "self_hosted"
  domain     = var.partner_hostname

  # R28 — the staff Allow is deliberately NOT attached here, and the service-auth policy is
  # deliberately not attached to the console. The two applications also carry different AUD
  # tags, which is the check the origin actually enforces (R22).
  policies = [
    {
      id         = cloudflare_zero_trust_access_policy.partner_service.id
      precedence = 1
    },
  ]
}

# ---------------------------------------------------------------------------------------
# Identity and public-surface controls
# ---------------------------------------------------------------------------------------

# R12 — one-time PIN, declared here rather than left as the account default so that R40's
# destroy/apply cycle rebuilds it like everything else.
#
# The justification, since R12 asks for one: OTP needs no OAuth application, no client
# secret to rotate, and no dependency on a third-party tenant staying reachable. For a clinic
# with six staff and no corporate directory, that is the whole appeal. The cost is real and
# worth stating plainly — the identity is an inbox, so account security is exactly the
# security of that inbox, there is no second factor, and there is no group membership to
# revoke centrally. Removing someone means editing the Allow list (R42's first drill), not
# disabling a directory account. A clinic that grows past this size should move to an OIDC
# provider; at six people the operational simplicity wins.
resource "cloudflare_zero_trust_access_identity_provider" "otp" {
  account_id = var.account_id
  name       = "One-time PIN"
  type       = "onetimepin"
  config     = {}
}

# R31 — Turnstile guards the public appointment form. Account-scoped, so unlike a WAF ruleset
# it is available on the free path with no zone. The secret never leaves state and .env; the
# sitekey is public by design and is what the page embeds.
resource "cloudflare_turnstile_widget" "public_form" {
  account_id = var.account_id
  name       = "meridian-public-form"
  mode       = "managed"
  domains    = var.turnstile_domains
}
