# Retrieve a specific local user by their numeric ID
data "clearpass_local_user" "example" {
  id = 1234
}

# Output the local user details
output "local_user_info" {
  value = data.clearpass_local_user.example
}
