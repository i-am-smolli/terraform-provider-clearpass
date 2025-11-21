# Local user with basic authentication
resource "clearpass_local_user" "john_doe" {
  user_id  = "jdoe"
  password = "SecurePassword123!"
  enabled  = true

  username    = "John Doe"
  role_name   = "Employee"
  email       = "john.doe@example.com"
  description = "Employee account for John Doe - IT Department"
}

# Guest user with expiration
resource "clearpass_local_user" "guest_visitor" {
  user_id  = "guest001"
  password = "GuestPass2024"
  enabled  = true

  username  = "Guest Visitor"
  role_name = "Guest"
}
