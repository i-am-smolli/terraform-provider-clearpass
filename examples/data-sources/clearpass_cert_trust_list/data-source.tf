# Retrieve a specific Certificate Trust List by its ID
data "clearpass_cert_trust_list" "example" {
  id = 2001
}

# Output the details of the retrieved certificate list
output "certificate_details" {
  value = data.clearpass_cert_trust_list.example
}
