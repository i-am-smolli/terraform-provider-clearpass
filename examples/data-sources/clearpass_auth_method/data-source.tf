# Retrieve a specific authentication method by its ID
data "clearpass_auth_method" "example" {
  id = "1"
}

# Output the details of the authentication method
# Use 'terraform output example_method' to see sensitive data
output "example_method" {
  value     = data.clearpass_auth_method.example
  sensitive = true # Required to output sensitive data
}