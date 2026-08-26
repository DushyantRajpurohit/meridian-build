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

output "partner_client_id" {
  description = "PARTNER_CLIENT_IDS, and the CF-Access-Client-Id the lab sends"
  value       = cloudflare_zero_trust_access_service_token.partner_lab.client_id
}

output "partner_client_secret" {
  description = "The lab's CF-Access-Client-Secret. Shown once by Cloudflare; kept out of logs here."
  value       = cloudflare_zero_trust_access_service_token.partner_lab.client_secret
  sensitive   = true
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
