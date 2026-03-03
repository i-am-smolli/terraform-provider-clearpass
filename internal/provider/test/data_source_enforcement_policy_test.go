package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccEnforcementPolicyDataSource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderConfig() + `
data "clearpass_enforcement_policy" "test" {
  id = 1
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.clearpass_enforcement_policy.test", "id"),
					resource.TestCheckResourceAttrSet("data.clearpass_enforcement_policy.test", "name"),
					resource.TestCheckResourceAttrSet("data.clearpass_enforcement_policy.test", "enforcement_type"),
					resource.TestCheckResourceAttrSet("data.clearpass_enforcement_policy.test", "default_enforcement_profile"),
					resource.TestCheckResourceAttrSet("data.clearpass_enforcement_policy.test", "rule_eval_algo"),
				),
			},
		},
	})
}
