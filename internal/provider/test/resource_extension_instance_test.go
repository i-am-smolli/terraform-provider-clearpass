// internal/provider/test/resource_extension_instance_test.go
package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccExtensionInstanceResource tests the creation, reading, updating, and importing of an ExtensionInstance.
func TestAccExtensionInstanceResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing with state "stopped"
			{
				Config: testAccProviderConfig() + `
resource "clearpass_extension_instance" "test_ext" {
  store_id = "com.example.test-extension"
  state    = "stopped"
  note     = "Terraform Acceptance Test"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("clearpass_extension_instance.test_ext", "id"),
					resource.TestCheckResourceAttr("clearpass_extension_instance.test_ext", "store_id", "com.example.test-extension"),
					resource.TestCheckResourceAttr("clearpass_extension_instance.test_ext", "state", "stopped"),
					resource.TestCheckResourceAttr("clearpass_extension_instance.test_ext", "note", "Terraform Acceptance Test"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "clearpass_extension_instance.test_ext",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update testing - change state to "running"
			{
				Config: testAccProviderConfig() + `
resource "clearpass_extension_instance" "test_ext" {
  store_id = "com.example.test-extension"
  state    = "running"
  note     = "Terraform Acceptance Test Updated"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_extension_instance.test_ext", "state", "running"),
					resource.TestCheckResourceAttr("clearpass_extension_instance.test_ext", "note", "Terraform Acceptance Test Updated"),
				),
			},
		},
	})
}
