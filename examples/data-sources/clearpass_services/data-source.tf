# Retrieve all services, calculating the total count
data "clearpass_services" "all" {
  calculate_count = true
}

# Retrieve services using a filter (e.g., matching a specific template type)
data "clearpass_services" "filtered" {
  filter = "{\"template\": \"RADIUS Enforcement ( Generic )\"}"
  sort   = "-id"
  limit  = 10
}

output "all_services_count" {
  value = data.clearpass_services.all.services
}

output "filtered_services_first_name" {
  value = try(data.clearpass_services.filtered.services[0].name, "none")
}
