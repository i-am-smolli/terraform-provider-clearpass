# Fetch all network device groups
data "clearpass_network_device_groups" "all" {
}

output "all_device_groups" {
  value = data.clearpass_network_device_groups.all.network_device_groups
}

# Fetch network device groups using a JSON filter
data "clearpass_network_device_groups" "filtered" {
  filter = "{\"name\":{\"$contains\":\"Switches\"}}"
}

output "switches_groups" {
  value = data.clearpass_network_device_groups.filtered.network_device_groups
}
