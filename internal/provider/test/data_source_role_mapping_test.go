package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccRoleMappingDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderConfig() + `
resource "clearpass_role_mapping" "test_rm_ds" {
  name              = "tf-acc-test-rm-ds"
  description       = "Terraform Acceptance Test Role Mapping DS"
  default_role_name = "[Guest]"
  rule_combine_algo = "first-applicable"
  rules = [
    {
      match_type = "OR"
      role_name  = "[Employee]"
      condition = [
        {
          type  = "Connection"
          name  = "Client-Mac-Address"
          oper  = "EXISTS"
          value = ""
        }
      ]
    }
  ]
}

data "clearpass_role_mapping" "test" {
  id = clearpass_role_mapping.test_rm_ds.id
}

data "clearpass_role_mappings" "all" {
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"data.clearpass_role_mapping.test", "id",
						"clearpass_role_mapping.test_rm_ds", "id",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_role_mapping.test", "name",
						"clearpass_role_mapping.test_rm_ds", "name",
					),
					// At least one role mapping should be returned in "all"
					resource.TestCheckResourceAttrSet("data.clearpass_role_mappings.all", "role_mappings.#"),
				),
			},
		},
	})
}
