# Example using the ID of the service
data "clearpass_service" "by_id" {
  id = 142
}

# Example using the exact name of the service
data "clearpass_service" "by_name" {
  name = "Guest Access Service"
}

output "clearpass_service_by_id_name" {
  value = data.clearpass_service.by_id.name
}

output "clearpass_service_by_name_id" {
  value = data.clearpass_service.by_name.id
}
