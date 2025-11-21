# Enforcement policy linking roles to profiles
resource "clearpass_enforcement_policy" "employee_policy" {
  name        = "Employee Access Policy"
  description = "Grant full access to employees on corporate network"
  enabled     = true

  rules = [
    {
      match_type = "AND"
      enforcement_profile_names = [
        "Employee Full Access"
      ]
      condition = [
        {
          type  = "Connection"
          name  = "SSID"
          oper  = "EQUALS"
          value = "Corporate-WiFi"
        }
      ]
    }
  ]
}

# Guest enforcement policy
resource "clearpass_enforcement_policy" "guest_policy" {
  name        = "Guest Internet Access"
  description = "Provide internet-only access for guest users"
  enabled     = true

  rules = [
    {
      match_type = "OR"
      enforcement_profile_names = [
        "Guest Internet Only"
      ]
      condition = [
        {
          type  = "UserRole"
          name  = "Role"
          oper  = "EQUALS"
          value = "Guest"
        }
      ]
    }
  ]
}
