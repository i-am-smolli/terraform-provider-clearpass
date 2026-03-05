data "clearpass_service_cert" "example" {
  id = 3000
}

output "service_cert" {
  value = data.clearpass_service_cert.example
}
