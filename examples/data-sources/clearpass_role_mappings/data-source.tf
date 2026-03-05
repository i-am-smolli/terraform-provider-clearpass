# Retrieve all role mappings
data "clearpass_role_mappings" "all" {
}

# Retrieve role mappings matching a JSON filter
data "clearpass_role_mappings" "filtered" {
  filter = "{\"name\":{\"$contains\":\"Guest\"}}"
}

output "clearpass_role_by_name" {
  value = data.clearpass_role_mappings.filtered
}