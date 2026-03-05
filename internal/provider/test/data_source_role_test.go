package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccRoleDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderConfig() + `
resource "clearpass_role" "test_role_ds" {
  name        = "tf-acc-test-role-ds"
  description = "Terraform Acceptance Test Role DS"
}

data "clearpass_role" "test" {
  id = clearpass_role.test_role_ds.id
}

data "clearpass_roles" "all" {
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"data.clearpass_role.test", "id",
						"clearpass_role.test_role_ds", "id",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_role.test", "name",
						"clearpass_role.test_role_ds", "name",
					),
					// At least one role should be returned in "all"
					resource.TestCheckResourceAttrSet("data.clearpass_roles.all", "roles.#"),
				),
			},
		},
	})
}
