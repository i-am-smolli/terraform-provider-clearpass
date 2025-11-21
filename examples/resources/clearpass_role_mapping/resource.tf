# Role mapping policy with first-applicable algorithm
resource "clearpass_role_mapping" "device_mapping" {
  name               = "Device-Based Role Mapping"
  description        = "Assigns roles based on device type and location"
  default_role_name  = "Guest"
  rule_combine_algo  = "first-applicable"

  rules = [
    {
      match_type = "AND"
      role_name  = "[Employee]"
      condition = [
        {
          type  = "Connection"
          name  = "SSID"
          oper  = "EQUALS"
          value = "Corporate-WiFi"
        },
        {
          type  = "Authentication"
          name  = "Source"
          oper  = "EQUALS"
          value = "ActiveDirectory"
        }
      ]
    },
    {
      match_type = "OR"
      role_name  = "Guest"
      condition = [
        {
          type  = "Connection"
          name  = "SSID"
          oper  = "EQUALS"
          value = "Guest-WiFi"
        }
      ]
    }
  ]
}
