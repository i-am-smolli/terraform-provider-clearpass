// internal/provider/resource_role_test.go
package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
)

// TestAccRoleResource tests the full CRUD and Import cycle for clearpass_role
func TestAccRoleResource(t *testing.T) {
	// Generate a unique name for the role to prevent conflicts
	uniqueName := acctest.RandomWithPrefix("tf-acc-role")
    
	// ClearPass often requires system roles to be bracketed, but API handles user-defined roles as strings.
	roleName := uniqueName 

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// 1. Create - Test initial creation with name and description
			{
				Config: testAccProviderConfig() + testAccRoleConfig(roleName, "Initial Test Role Description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check the name matches the config
					resource.TestCheckResourceAttr("clearpass_role.test_role", "name", roleName),
					// Check the description matches
					resource.TestCheckResourceAttr("clearpass_role.test_role", "description", "Initial Test Role Description"),
					// Check that a numeric ID was generated
					resource.TestCheckResourceAttrSet("clearpass_role.test_role", "id"),
				),
			},
			// 2. Update - Change only the description field
			{
				Config: testAccProviderConfig() + testAccRoleConfig(roleName, "Updated Description for Role"),
				Check: resource.ComposeAggregateTestCheckFunc(
					// Ensure the name is unchanged
					resource.TestCheckResourceAttr("clearpass_role.test_role", "name", roleName),
					// Ensure the description is updated
					resource.TestCheckResourceAttr("clearpass_role.test_role", "description", "Updated Description for Role"),
				),
			},
			// 3. Import State - Test 'terraform import' functionality
			{
				ResourceName:      "clearpass_role.test_role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// HCL configuration helper function
func testAccRoleConfig(name, description string) string {
	return `
resource "clearpass_role" "test_role" {
  name        = "` + name + `"
  description = "` + description + `"
}
`
}