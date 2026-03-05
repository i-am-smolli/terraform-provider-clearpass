package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataSourceEnforcementProfiles(t *testing.T) {
	uniqueName := acctest.RandomWithPrefix("tf-acc-ds-profiles")

	config := testAccProviderConfig() + testAccEnforcementProfileConfig(uniqueName, "Testing plural DS", "555") +
		`
data "clearpass_enforcement_profiles" "all" {}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.clearpass_enforcement_profiles.all", "id"),
					resource.TestCheckResourceAttrSet("data.clearpass_enforcement_profiles.all", "items.#"),
				),
			},
		},
	})
}
