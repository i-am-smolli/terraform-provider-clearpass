# Retrieve all service certificates from ClearPass
data "clearpass_service_certs" "all" {}

# Output the list of service certificates
output "service_certs" {
  value = data.clearpass_service_certs.all.service_certs
}
