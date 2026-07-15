package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccAdminPrivilegeResource(t *testing.T) {
	uniqueName := acctest.RandomWithPrefix("tf-acc-priv")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// 1. Create
			{
				Config: testAccProviderConfig() + testAccAdminPrivilegeConfig(uniqueName, "Initial Privilege Description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "name", uniqueName),
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "description", "Initial Privilege Description"),
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "access_type", "FULL"),
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "cppm_privileges.con", "RW"),
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "cppm_privileges.mon", "R"),
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "allow_passwords", "false"),
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "allow_security_configs", "true"),
					resource.TestCheckResourceAttrSet("clearpass_admin_privilege.test", "id"),
				),
			},
			// 2. Update
			{
				Config: testAccProviderConfig() + testAccAdminPrivilegeConfigUpdate(uniqueName, "Updated Privilege Description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "name", uniqueName),
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "description", "Updated Privilege Description"),
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "access_type", "UI"),
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "cppm_privileges.con", "RWD"),
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "cppm_privileges.mon", "RW"),
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "allow_passwords", "true"),
					resource.TestCheckResourceAttr("clearpass_admin_privilege.test", "allow_security_configs", "false"),
				),
			},
			// 3. Import
			{
				ResourceName:      "clearpass_admin_privilege.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccAdminPrivilegeConfig(name, description string) string {
	return `
resource "clearpass_admin_privilege" "test" {
  name        = "` + name + `"
  description = "` + description + `"
  access_type = "FULL"
  cppm_privileges = {
    "con" = "RW"
    "mon" = "R"
  }
  allow_passwords        = false
  allow_security_configs = true
}
`
}

func testAccAdminPrivilegeConfigUpdate(name, description string) string {
	return `
resource "clearpass_admin_privilege" "test" {
  name        = "` + name + `"
  description = "` + description + `"
  access_type = "UI"
  cppm_privileges = {
    "con" = "RWD"
    "mon" = "RW"
  }
  allow_passwords        = true
  allow_security_configs = false
}
`
}
