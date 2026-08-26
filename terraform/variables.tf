variable "account_id" {
  description = "Cloudflare account id. Not a secret, but it lives in tfvars with everything else."
  type        = string
}

variable "pages_project_name" {
  description = "Pages project name. Becomes <name>.pages.dev."
  type        = string
  default     = "meridian-clinic"
}

variable "staff_emails" {
  description = "R13 — the named staff, and nobody else. Access decides at the edge; the origin checks again."
  type        = list(string)
}

variable "blocked_emails" {
  description = <<-EOT
    R14 — addresses that must be refused even though they would otherwise match the Allow.
    The Block policy carrying these sits at precedence 1, above the Allow at 2. Reverse the
    two and the Block never fires, because evaluation stops at the first match.
  EOT
  type        = list(string)
  default     = []
}

variable "admin_hostname" {
  description = "The Access-protected hostname for the staff console, e.g. staff.meridian-clinic.pages.dev."
  type        = string
}

variable "partner_hostname" {
  description = "The Access-protected hostname for the partner API."
  type        = string
}

variable "staff_session_duration" {
  description = <<-EOT
    R15 — deliberately 8 hours, which is one shift.

    The threat here is not a stolen token; it is a clinic workstation left unattended, or a
    laptop taken home and lost. Session length is the only control that bounds that exposure
    without a device-posture product we do not have on the free plan. Eight hours means a
    session cannot outlive the shift that created it, so the night staff never inherit the
    morning's login.

    Shorter was tempting and is the wrong trade: with one-time PIN as the identity provider,
    re-authenticating costs an email round trip every time, and a console that logs people out
    hourly in the middle of clinical work is a console people prop open — or share an already
    authenticated browser to avoid. That is a worse outcome than a slightly longer window.
  EOT
  type        = string
  default     = "8h"
}

variable "turnstile_domains" {
  description = <<-EOT
    R31 — hostnames allowed to solve this widget. Turnstile validates the domain at
    siteverify, so a sitekey lifted from the page is not usable from an attacker's own site.
    localhost is included deliberately: the rehearsal runs the form locally, and dropping it
    would mean testing a different widget from the one that ships.
  EOT
  type        = list(string)
  default     = ["meridian-clinic.pages.dev", "localhost"]
}

variable "partner_session_duration" {
  description = <<-EOT
    The partner application admits service tokens only, so no browser session is ever
    established here and this value governs nothing in practice. It is set anyway, at the
    provider's own default, so that the value is mine rather than inherited — a default that
    changes in a future provider release should show up as a diff in a plan, not as a silent
    change to a security control.
  EOT
  type        = string
  default     = "24h"
}

variable "operator_email" {
  description = <<-EOT
    R36 — the single identity allowed to enrol a device and reach the box's operations
    address. Deliberately one address and not `staff_emails`: the requirement is "your
    identity, not everyone enrolled in the team", and clinic staff reach the console with a
    browser and a URL, never with a route into the machine.
  EOT
  type        = string
}

variable "private_host_ip" {
  description = "R35 — the box's operations address, held on `lo` so it is never ARPed onto the LAN."
  type        = string
  default     = "10.99.0.1"
}

variable "private_host_cidr" {
  description = <<-EOT
    R35 — what the tunnel is authorised to forward to. A /32 rather than a /24: the route is
    permission to forward, and everything inside it is reachable from the connector's network
    namespace, which on this box would mean the LAN. One address is the honest size of what is
    being exposed.
  EOT
  type        = string
  default     = "10.99.0.1/32"
}
