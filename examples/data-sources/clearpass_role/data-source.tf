# Example using the ID of the role
data "clearpass_role" "by_id" {
  id = 12
}

# Example using the exact name of the role
data "clearpass_role" "by_name" {
  name = "[Employee]"
}

output "clearpass_role_by_id" {
  value = data.clearpass_role.by_id.name
}

output "clearpass_role_by_name" {
  value = data.clearpass_role.by_name.id
}