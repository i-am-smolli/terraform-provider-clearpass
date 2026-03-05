# Example for fetching a single enforcement profile by name
data "clearpass_enforcement_profile" "employee_access" {
  name = "Employee-Access-Profile"
}

output "employee_profile_action" {
  description = "The action taken by the employee profile"
  value       = data.clearpass_enforcement_profile.employee_access.action
}

# Example for fetching a single enforcement profile by ID
data "clearpass_enforcement_profile" "guest_access" {
  id = 123
}

output "guest_profile_type" {
  description = "The type of the guest profile"
  value       = data.clearpass_enforcement_profile.guest_access.type
}
