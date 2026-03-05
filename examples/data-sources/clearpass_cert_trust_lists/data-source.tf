# Retrieve all Certificate Trust Lists from ClearPass
data "clearpass_cert_trust_lists" "all" {}

# Output the list of certificates
output "all_certificates" {
  value = data.clearpass_cert_trust_lists.all.lists
}
