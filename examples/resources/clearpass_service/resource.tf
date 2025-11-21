# 802.1X service for wired and wireless authentication
resource "clearpass_service" "dot1x_service" {
  name         = "802.1X Authentication"
  description  = "Standard 802.1X authentication service for wired and wireless networks"
  enabled      = true
  service_type = "802.1X"

  monitor_mode    = false
  audit_enabled   = true
  profiler_enabled = true
}

# MAC Authentication Bypass (MAB) service
resource "clearpass_service" "mab_service" {
  name         = "MAC Authentication"
  description  = "MAC Authentication Bypass for devices without 802.1X support"
  enabled      = true
  service_type = "MAB"

  monitor_mode     = false
  audit_enabled    = false
  profiler_enabled = true
}

# Guest portal service with posture assessment
resource "clearpass_service" "guest_portal" {
  name         = "Guest Self-Registration"
  description  = "Self-service guest registration portal with device posture checks"
  enabled      = true
  service_type = "Guest"

  posture_enabled = true
  audit_enabled   = true
  profiler_enabled = false
}
