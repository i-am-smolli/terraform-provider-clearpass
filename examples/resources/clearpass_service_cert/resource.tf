resource "clearpass_service_cert" "example" {
  certificate_url   = "https://example.com/cert.pem"
  pkcs12_file_url   = "https://example.com/key.p12"
  pkcs12_passphrase = "secret-passphrase"
}
