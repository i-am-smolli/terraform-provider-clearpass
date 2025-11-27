resource "clearpass_auth_method" "eap_tls" {
  name = "EAP-TLS-Method"
  description = "EAP-TLS Authentication Method for Corporate Devices"
  method_type = "EAP-TLS"

  details {
    autz_required = true
    session_cache_enable = true
    session_timeout = 5
    certificate_comparison = "none"
    ocsp_enable = "optional"
  }
}
