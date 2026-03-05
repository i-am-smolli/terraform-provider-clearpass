# Retrieve a specific role mapping by its numeric ID
data "clearpass_role_mapping" "by_id" {
  id = 2001
}

# Retrieve a specific role mapping by its exact name
data "clearpass_role_mapping" "by_name" {
  name = "[Guest Roles]"
}

# Output the default role assigned by the role mapping
output "default_role" {
  value = data.clearpass_role_mapping.by_name.default_role_name
}

# Output the number of rules in the role mapping
output "rule_count" {
  value = length(data.clearpass_role_mapping.by_name.rules)
}
