// internal/provider/resource_enforcement_profile_test.go
package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccEnforcementProfileResource(t *testing.T) {
	// Generate a unique name
	uniqueName := acctest.RandomWithPrefix("tf-acc-enforce")

	// Configuration 1: Initial Creation (VLAN ID 100)
	config1 := testAccProviderConfig() + testAccEnforcementProfileConfig(uniqueName, "Initial Profile", "100")

	// Configuration 2: Update (VLAN ID 150 and description changed)
	config2 := testAccProviderConfig() + testAccEnforcementProfileConfig(uniqueName, "Updated Profile", "150")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// 1. Create - Test initial creation with two attributes
			{
				Config: config1,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_enforcement_profile.test_profile", "name", uniqueName),
					resource.TestCheckResourceAttr("clearpass_enforcement_profile.test_profile", "description", "Initial Profile"),
					// Check nested list count and a specific attribute value
					resource.TestCheckResourceAttr("clearpass_enforcement_profile.test_profile", "attributes.#", "2"),
					resource.TestCheckResourceAttr("clearpass_enforcement_profile.test_profile", "attributes.1.value", "100"), // Check VLAN ID value
					resource.TestCheckResourceAttrSet("clearpass_enforcement_profile.test_profile", "id"),
				),
			},
			// 2. Update - Change description and one nested attribute value
			{
				Config: config2,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check simple field update
					resource.TestCheckResourceAttr("clearpass_enforcement_profile.test_profile", "description", "Updated Profile"),
					// Check nested attribute update (VLAN ID changed to 150)
					resource.TestCheckResourceAttr("clearpass_enforcement_profile.test_profile", "attributes.1.value", "150"),
					// Ensure the first attribute (Filter-Id) remains unchanged
					resource.TestCheckResourceAttr("clearpass_enforcement_profile.test_profile", "attributes.0.value", "Employee-Access"),
				),
			},
			// 3. Import State - Test 'terraform import' functionality
			{
				ResourceName:      "clearpass_enforcement_profile.test_profile",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// HCL configuration helper function.
func testAccEnforcementProfileConfig(name, description, vlanID string) string {
	return `
resource "clearpass_enforcement_profile" "test_profile" {
  name        = "` + name + `"
  description = "` + description + `"
  type        = "RADIUS"
  action      = "Accept"

  attributes = [
    {
      type  = "Radius:IETF"
      name  = "Filter-Id"
      value = "Employee-Access"
    },
    {
      type  = "Radius:IETF"
      name  = "Tunnel-Private-Group-Id"
      value = "` + vlanID + `" // This value will change during the update step
    }
  ]
}
`
}
