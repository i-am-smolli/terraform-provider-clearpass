resource "clearpass_role" "employee" {
  name        = "[Employee]"
  description = "Role assigned to company employees with full network access"
}

resource "clearpass_role" "guest" {
  name        = "Guest"
  description = "Limited access role for guest users"
}
