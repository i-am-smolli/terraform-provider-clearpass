resource "clearpass_local_user" "john_doe" {
  user_id   = "jdoe"
  username  = "John Doe"
  password  = "SecretPassword123!"
  role_name = "[Employee]"
  enabled   = true

  attributes = {
    "Department" = "Engineering"
    "Location"   = "HQ"
  }
}
