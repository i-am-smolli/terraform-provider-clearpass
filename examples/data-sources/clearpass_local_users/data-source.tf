# Retrieve all local users from ClearPass
data "clearpass_local_users" "all" {}

# Output the list of all local users
output "all_local_users" {
  value = data.clearpass_local_users.all.items
}
