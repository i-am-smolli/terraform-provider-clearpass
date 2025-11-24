package provider_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccServiceResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read
			{
				Config: testAccServiceResourceConfig("TF Service Test", "RADIUS Enforcement ( Generic )"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_service.test_service", "name", "TF Service Test"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "template", "RADIUS Enforcement ( Generic )"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "enabled", "true"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "strip_username", "false"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "match_type", "MATCHES_ANY"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "auth_methods.0", "[EAP PEAP]"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "auth_methods.1", "[EAP FAST]"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "auth_methods.1", "[EAP FAST]"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "auth_methods.1", "[EAP FAST]"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "auth_sources.0", "[Local User Repository]"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "monitor_mode", "true"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "posture_enabled", "false"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "audit_enabled", "false"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "profiler_enabled", "false"),
				),
			},
			// Update and Read
			{
				Config: testAccServiceResourceConfig("TF Service Updated", "RADIUS Enforcement ( Generic )"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_service.test_service", "name", "TF Service Updated"),
					resource.TestCheckResourceAttr("clearpass_service.test_service", "template", "RADIUS Enforcement ( Generic )"),
				),
			},
			// Import
			{
				ResourceName:      "clearpass_service.test_service",
				ImportState:       true,
				ImportStateVerify: true,
				// Ignore computed fields or fields that might not be returned exactly as set if needed
				ImportStateVerifyIgnore: []string{"auth_methods", "auth_sources", "service_rule"},
			},
		},
	})
}

func testAccServiceResourceConfig(name, template string) string {
	return testAccProviderConfig() + fmt.Sprintf(`
resource "clearpass_enforcement_profile" "p1" {
  name        = "TF_Acc_Profile_For_Service"
  description = "Profile for Service Acc Test"
  type        = "RADIUS"
  action      = "Accept"
  attributes  = [
    {
      type  = "Radius:IETF"
      name  = "Filter-Id"
      value = "Test-Allow-All"
    }
  ]
}

resource "clearpass_enforcement_policy" "pol1" {
  name                      = "TF_Acc_Policy_For_Service"
  description               = "Policy for Service Acc Test"
  enforcement_type          = "RADIUS"
  default_enforcement_profile = clearpass_enforcement_profile.p1.name
  rule_eval_algo            = "first-applicable"
  rules = [
    {
      enforcement_profile_names = [clearpass_enforcement_profile.p1.name]
      condition = [
        {
          type  = "Connection"
          name  = "SSID"
          oper  = "EQUALS"
          value = "Test-SSID"
        }
      ]
    }
  ]
}

resource "clearpass_service" "test_service" {
  name               = "%s"
  template           = "%s"
  description        = "Acceptance Test Service"
  enabled            = true
  strip_username     = false
  match_type         = "MATCHES_ANY"

  auth_methods       = ["[EAP PEAP]", "[EAP FAST]"]
  auth_sources       = ["[Local User Repository]"]

  monitor_mode       = true
  posture_enabled    = false
  audit_enabled      = false
  profiler_enabled   = false

  enforcement_policy = clearpass_enforcement_policy.pol1.name

  service_rule = [{
    type     = "Radius:IETF"
    name     = "NAS-Port-Type"
    operator = "EQUALS"
    value    = "Wireless-802.11 (19)"
  }]
}
`, name, template)
}
