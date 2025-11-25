resource "clearpass_cert_trust_list" "example" {
  cert_file = file("${path.module}/ca_cert.pem")
  enabled   = true
  cert_usage = [
    "EAP",
    "RadSec",
    "Database"
  ]
}
