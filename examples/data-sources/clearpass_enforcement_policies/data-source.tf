# Retrieve all Enforcement Policies from ClearPass
data "clearpass_enforcement_policies" "all" {}

# Output the list of policies
output "all_enforcement_policies" {
  value = data.clearpass_enforcement_policies.all.policies
}
