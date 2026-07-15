package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccAdminPrivilegeDataSource(t *testing.T) {
	uniqueName := acctest.RandomWithPrefix("tf-acc-priv-ds")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderConfig() + `
resource "clearpass_admin_privilege" "test_priv_ds" {
  name        = "` + uniqueName + `"
  description = "Terraform Acceptance Test Privilege DS"
  access_type = "API"
  cppm_privileges = {
    "mon" = "R"
  }
}

data "clearpass_admin_privilege" "test_by_id" {
  id = clearpass_admin_privilege.test_priv_ds.id
}

data "clearpass_admin_privilege" "test_by_name" {
  name = clearpass_admin_privilege.test_priv_ds.name
}

data "clearpass_admin_privileges" "all" {
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"data.clearpass_admin_privilege.test_by_id", "id",
						"clearpass_admin_privilege.test_priv_ds", "id",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_admin_privilege.test_by_id", "name",
						"clearpass_admin_privilege.test_priv_ds", "name",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_admin_privilege.test_by_name", "id",
						"clearpass_admin_privilege.test_priv_ds", "id",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_admin_privilege.test_by_name", "name",
						"clearpass_admin_privilege.test_priv_ds", "name",
					),
					resource.TestCheckResourceAttrSet("data.clearpass_admin_privileges.all", "admin_privileges.#"),
				),
			},
		},
	})
}
