resource "clearpass_enforcement_policy" "example" {
  name                      = "Example Policy"
  description               = "Policy for example purposes"
  enforcement_type          = "RADIUS"
  default_enforcement_profile = "Allow Access Profile"
  rule_eval_algo            = "first-applicable"

  rules = [
    {
      enforcement_profile_names = ["Deny Access Profile"]
      condition = [
        {
          type  = "Tips"
          name  = "Role"
          oper  = "EQUALS"
          value = "Guest"
        }
      ]
    }
  ]
}
