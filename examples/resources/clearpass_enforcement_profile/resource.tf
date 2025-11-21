# RADIUS enforcement profile with custom attributes
resource "clearpass_enforcement_profile" "employee_access" {
  name        = "Employee Full Access"
  description = "Full network access for authenticated employees"
  type        = "RADIUS"
  action      = "Accept"

  attributes = [
    {
      type  = "Radius:IETF"
      name  = "Filter-Id"
      value = "employee-acl"
    },
    {
      type  = "Radius:IETF"
      name  = "Session-Timeout"
      value = "28800"  # 8 hours
    }
  ]
}

# Guest enforcement profile with restricted access
resource "clearpass_enforcement_profile" "guest_limited" {
  name        = "Guest Internet Only"
  description = "Limited access for guest users - Internet only"
  type        = "RADIUS"
  action      = "Accept"

  device_group_list = ["Guest-Devices", "BYOD"]

  attributes = [
    {
      type  = "Radius:IETF"
      name  = "Filter-Id"
      value = "guest-internet-only"
    },
    {
      type  = "Radius:IETF"
      name  = "Session-Timeout"
      value = "3600"  # 1 hour
    }
  ]
}

# Agent-based enforcement profile
resource "clearpass_enforcement_profile" "posture_check" {
  name           = "Endpoint Posture Check"
  description    = "OnGuard agent-based posture assessment"
  type           = "Agent"
  agent_template = "Agent"
}
