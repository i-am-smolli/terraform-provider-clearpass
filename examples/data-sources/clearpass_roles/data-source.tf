# Fetch all roles
data "clearpass_roles" "all" {
}

output "first_role_name" {
  value = data.clearpass_roles.all.roles[0].name
}

# Fetch roles using a JSON filter
data "clearpass_roles" "filtered" {
  filter = "{\"name\":{\"$contains\":\"Admin\"}}"
}

output "admin_roles" {
  value = data.clearpass_roles.filtered.roles
}
