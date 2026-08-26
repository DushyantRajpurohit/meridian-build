# These feed .env. The AUD tags are what the origin pins per application (R19/R22), so a
# copy-paste error here is a 403 on every request rather than a silent weakening.

output "access_aud_admin" {
  description = "ACCESS_AUD_ADMIN"
  value       = cloudflare_zero_trust_access_application.admin.aud
}

output "access_aud_partner" {
  description = "ACCESS_AUD_PARTNER"
  value       = cloudflare_zero_trust_access_application.partner.aud
}

output "kv_namespace_id" {
  description = "CF_KV_NAMESPACE_ID, and the id wrangler.toml needs"
  value       = cloudflare_workers_kv_namespace.meridian.id
}

output "pages_subdomain" {
  description = "The canonical hostname — the one Access does NOT protect (R16, R24)"
  value       = cloudflare_pages_project.clinic.subdomain
}

output "turnstile_sitekey" {
  description = "TURNSTILE_SITEKEY — public, embedded in the appointment form"
  value       = cloudflare_turnstile_widget.public_form.sitekey
}

output "turnstile_secret" {
  description = "TURNSTILE_SECRET — server side, used at siteverify"
  value       = cloudflare_turnstile_widget.public_form.secret
  sensitive   = true
}

output "reviewer_client_id" {
  description = "Deliverable 3 — the reviewer's CF-Access-Client-Id, partner API only"
  value       = cloudflare_zero_trust_access_service_token.reviewer.client_id
}

output "reviewer_client_secret" {
  description = "Deliverable 3 — the reviewer's CF-Access-Client-Secret"
  value       = cloudflare_zero_trust_access_service_token.reviewer.client_secret
  sensitive   = true
}

output "partner_client_id_2" {
  description = "R42 drill 2 — the replacement partner credential, valid alongside the original."
  value       = cloudflare_zero_trust_access_service_token.partner_lab_2.client_id
}

output "partner_client_secret_2" {
  value     = cloudflare_zero_trust_access_service_token.partner_lab_2.client_secret
  sensitive = true
}

output "private_tunnel_id" {
  description = "R8/R35 — the named tunnel the systemd connector runs. Not a secret."
  value       = cloudflare_zero_trust_tunnel_cloudflared.private.id
}

output "private_tunnel_token" {
  description = <<-EOT
    R9 — the connector token. A secret, and the more dangerous of the two artefacts: it is one
    line, it is designed to be pasted, and on a remotely-managed tunnel it also fetches the
    ingress configuration. scripts/root-setup.sh reads it through this output into a 0600
    EnvironmentFile and never onto a command line.
  EOT
  value       = data.cloudflare_zero_trust_tunnel_cloudflared_token.private.token
  sensitive   = true
}

output "private_host_ip" {
  description = "R35 — the address a WARP-enrolled operator reaches the box on."
  value       = var.private_host_ip
}
