// internal/provider/resource_local_user_test.go
package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccLocalUserResource(t *testing.T) {
	// Step 1: Create
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// 1. Create a user
			{
				Config: testAccProviderConfig() + `
resource "clearpass_local_user" "test" {
  user_id   = "tf-acc-test-user"
  username  = "tf-acc-test-user"
  password  = "SecretPassword123!"
  role_name = "[Employee]"
  enabled   = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check that the state matches what we expect
					resource.TestCheckResourceAttr("clearpass_local_user.test", "user_id", "tf-acc-test-user"),
					resource.TestCheckResourceAttr("clearpass_local_user.test", "role_name", "[Employee]"),
					resource.TestCheckResourceAttr("clearpass_local_user.test", "enabled", "true"),
					// Check that an ID was generated (it shouldn't be empty)
					resource.TestCheckResourceAttrSet("clearpass_local_user.test", "id"),
				),
			},
			// 2. Update the user (Disable it)
			{
				Config: testAccProviderConfig() + `
resource "clearpass_local_user" "test" {
  user_id   = "tf-acc-test-user"
  username  = "tf-acc-test-user"
  password  = "SecretPassword123!"
  role_name = "[Employee]"
  enabled   = false 
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_local_user.test", "enabled", "false"),
				),
			},
			// 3. Import State (verify 'terraform import' works)
			{
				ResourceName:      "clearpass_local_user.test",
				ImportState:       true,
				ImportStateVerify: true,
				// Password is sensitive/write-only, so we ignore it during import check
				ImportStateVerifyIgnore: []string{"password"},
			},
		},
	})
}
