resource "clearpass_service" "dot1x" {
  name         = "802.1X Wireless Authentication"
  description  = "Enterprise wireless authentication"
  enabled      = true
  service_type = "802.1X"
  template     = "802.1X Wireless"

  monitor_mode     = false
  audit_enabled    = true
  profiler_enabled = true
}
