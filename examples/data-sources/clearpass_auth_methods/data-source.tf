# Retrieve a list of all authentication methods
data "clearpass_auth_methods" "all" {}

# Output the list of all methods
# Use 'terraform output all_auth_methods' to see sensitive data
output "all_auth_methods" {
  value     = data.clearpass_auth_methods.all.auth_methods
  sensitive = true # Required to output sensitive data
}
