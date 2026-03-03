data "clearpass_local_users" "all" {
}

output "all_local_users" {
  value = data.clearpass_local_users.all.items
}
