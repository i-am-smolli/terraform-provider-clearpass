resource "clearpass_enforcement_profile" "radius_profile" {
  name        = "TF RADIUS Profile"
  description = "Created via Terraform"
  type        = "RADIUS"
  action      = "Accept"

  attributes = [
    {
      type  = "Radius:IETF"
      name  = "Tunnel-Type"
      value = "VLAN (13)"
    },
    {
      type  = "Radius:IETF"
      name  = "Tunnel-Medium-Type"
      value = "IEEE-802 (6)"
    },
    {
      type  = "Radius:IETF"
      name  = "Tunnel-Private-Group-Id"
      value = "450"
    },
  ]
}
