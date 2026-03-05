# Retrieve a specific Enforcement Policy by its ID
data "clearpass_enforcement_policy" "example" {
  id = 123
}

# Output the details of the retrieved enforcement policy
output "enforcement_policy_details" {
  value = data.clearpass_enforcement_policy.example
}
