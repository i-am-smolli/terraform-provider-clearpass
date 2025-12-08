resource "clearpass_service_cert" "example_url" {
  pkcs12_file_url   = "https://example.com/key.p12"
  pkcs12_passphrase = "secret-passphrase"
}

# This will spawn a local HTTP server listening on port 80 to serve the file to ClearPass.
resource "clearpass_service_cert" "example_local_file" {
  pkcs12_file_base64 = filebase64("${path.module}/cert.pfx")
  pkcs12_passphrase  = "secret-passphrase"
  port               = 80 # may require privileges to bind to ports < 1024
}
