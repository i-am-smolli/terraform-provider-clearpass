// internal/provider/resource_role_mapping_test.go
package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
)
func TestAccRoleMappingResource(t *testing.T) {

	uniqueName := acctest.RandomWithPrefix("tf-acc-role-map") 

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// 1. CREATE: Valid initial configuration (2 rules)
			{
				Config: testAccProviderConfig() + testAccRoleMappingConfigClean(uniqueName, "TF Initial Policy"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_role_mapping.test_map", "name", uniqueName),
					resource.TestCheckResourceAttr("clearpass_role_mapping.test_map", "rules.#", "2"),
					resource.TestCheckResourceAttr("clearpass_role_mapping.test_map", "rules.0.match_type", "AND"),
					resource.TestCheckResourceAttrSet("clearpass_role_mapping.test_map", "id"),
				),
			},
			// 2. UPDATE: Change Description
			{
				Config: testAccProviderConfig() + testAccRoleMappingConfigClean(uniqueName, "Updated Description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_role_mapping.test_map", "description", "Updated Description"),
				),
			},
			// 3. Import State (verify 'terraform import' works)
			{
				ResourceName:      "clearpass_role_mapping.test_map",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// Helper function simplified for clean execution (always 2 rules and correct logic)
func testAccRoleMappingConfigClean(name, description string) string {
	return `
resource "clearpass_role_mapping" "test_map" {
  name              = "` + name + `"
  description       = "` + description + `"
  default_role_name = "[Guest]"
  rule_combine_algo = "evaluate-all"

  rules = [
    {
      match_type = "AND" 
      role_name  = "[Employee]"
      condition  = [
        {
          type  = "Connection"
          name  = "Client-Mac-Address"
          oper  = "EXISTS"
          value = ""
        },
        {
          type  = "Application"
          name  = "Name"
          oper  = "EQUALS"
          value = "SSO"
        }
      ]
    },
    {
      match_type = "OR"
      role_name  = "[Contractor]"
      condition  = [{
        type  = "Authentication"
        name  = "ErrorCode"
        oper  = "EQUALS"
        value = "0"
      }]
    }
  ]
}
`
}