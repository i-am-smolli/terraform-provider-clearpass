# Employee role with full network access
resource "clearpass_role" "employee" {
  name        = "[Employee]"
  description = "Full network access for company employees"
}

# Guest role with limited access
resource "clearpass_role" "guest" {
  name        = "Guest"
  description = "Limited access for guest users with internet-only permissions"
}

# Contractor role
resource "clearpass_role" "contractor" {
  name        = "[Contractor]"
  description = "Limited access role for contractors and temporary workers"
}
