data "clearpass_service_certs" "all" {
}

output "service_certs" {
  value = data.clearpass_service_certs.all.service_certs
}

