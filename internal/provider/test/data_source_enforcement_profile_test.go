package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataSourceEnforcementProfile(t *testing.T) {
	uniqueName := acctest.RandomWithPrefix("tf-acc-ds-profile")

	config := testAccProviderConfig() + testAccEnforcementProfileConfig(uniqueName, "Testing DS", "123") +
		`
data "clearpass_enforcement_profile" "by_id" {
  id = clearpass_enforcement_profile.test_profile.id
}

data "clearpass_enforcement_profile" "by_name" {
  name = clearpass_enforcement_profile.test_profile.name
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"data.clearpass_enforcement_profile.by_id", "id",
						"clearpass_enforcement_profile.test_profile", "id",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_enforcement_profile.by_id", "name",
						"clearpass_enforcement_profile.test_profile", "name",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_enforcement_profile.by_id", "description",
						"clearpass_enforcement_profile.test_profile", "description",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_enforcement_profile.by_id", "type",
						"clearpass_enforcement_profile.test_profile", "type",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_enforcement_profile.by_id", "action",
						"clearpass_enforcement_profile.test_profile", "action",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_enforcement_profile.by_name", "id",
						"clearpass_enforcement_profile.test_profile", "id",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_enforcement_profile.by_name", "name",
						"clearpass_enforcement_profile.test_profile", "name",
					),
				),
			},
		},
	})
}
