package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccEnforcementPolicyDataSource_basic(t *testing.T) {
	uniqueName := acctest.RandomWithPrefix("tf-acc-ds-ep")
	profileName := uniqueName + "-prof"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderConfig() + `
resource "clearpass_enforcement_profile" "dep_profile_ds" {
  name        = "` + profileName + `"
  description = "Dependency for EP DS Test"
  type        = "RADIUS"
  action      = "Accept"
  attributes  = [{ type = "Radius:IETF", name = "Filter-Id", value = "Test-Allow" }]
}

resource "clearpass_enforcement_policy" "test_ep_ds" {
  name                        = "` + uniqueName + `"
  description                 = "Terraform Acceptance Test EP DS"
  enforcement_type            = "RADIUS"
  default_enforcement_profile = "[Deny Access Profile]"
  rule_eval_algo              = "first-applicable"
  rules = [
    {
      enforcement_profile_names = [clearpass_enforcement_profile.dep_profile_ds.name]
      condition = [{
        type  = "Connection"
        name  = "SSID"
        oper  = "EQUALS"
        value = "Test-SSID"
      }]
    }
  ]
}

data "clearpass_enforcement_policy" "test" {
  id = clearpass_enforcement_policy.test_ep_ds.id
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"data.clearpass_enforcement_policy.test", "id",
						"clearpass_enforcement_policy.test_ep_ds", "id",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_enforcement_policy.test", "name",
						"clearpass_enforcement_policy.test_ep_ds", "name",
					),
					resource.TestCheckResourceAttrSet("data.clearpass_enforcement_policy.test", "enforcement_type"),
					resource.TestCheckResourceAttrSet("data.clearpass_enforcement_policy.test", "default_enforcement_profile"),
					resource.TestCheckResourceAttrSet("data.clearpass_enforcement_policy.test", "rule_eval_algo"),
				),
			},
		},
	})
}
