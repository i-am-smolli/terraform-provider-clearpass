resource "clearpass_role_mapping" "device_based" {
  name              = "Device-Based Role Assignment"
  description       = "Assign roles based on device type"
  default_role_name = "Guest"
  rule_combine_algo = "first-applicable"

  rules = [
    {
      match_type = "OR"
      role_name  = "[Employee]"
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
