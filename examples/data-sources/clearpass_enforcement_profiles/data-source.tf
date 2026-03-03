# Example for fetching all enforcement profiles
data "clearpass_enforcement_profiles" "all_profiles" {}

output "total_profiles" {
  description = "The total number of enforcement profiles"
  value       = length(data.clearpass_enforcement_profiles.all_profiles.items)
}

output "first_profile_name" {
  description = "The name of the first enforcement profile"
  value       = data.clearpass_enforcement_profiles.all_profiles.items[0].name
}
