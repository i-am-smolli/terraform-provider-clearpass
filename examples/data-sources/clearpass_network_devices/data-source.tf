# Fetch all network devices
data "clearpass_network_devices" "all" {
}

output "all_devices" {
  value = data.clearpass_network_devices.all.network_devices
}

# Fetch network devices using a JSON filter
data "clearpass_network_devices" "filtered" {
  filter = "{\"name\":{\"$contains\":\"Aruba\"}}"
}

output "aruba_devices" {
  value = data.clearpass_network_devices.filtered.network_devices
}
