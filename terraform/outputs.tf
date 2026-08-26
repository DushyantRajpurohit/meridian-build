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
