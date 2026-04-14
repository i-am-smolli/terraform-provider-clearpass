// internal/provider/test/resource_extension_instance_config_test.go
package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccExtensionInstanceConfigResource tests create, update, and import of an ExtensionInstanceConfig.
func TestAccExtensionInstanceConfigResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccProviderConfig() + `
resource "clearpass_extension_instance" "cfg_parent" {
  store_id = "com.example.test-extension"
  state    = "stopped"
}

resource "clearpass_extension_instance_config" "test_cfg" {
  instance_id = clearpass_extension_instance.cfg_parent.id
  config_json = jsonencode({
    enabled = true
    level   = "info"
  })
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("clearpass_extension_instance_config.test_cfg", "id"),
					resource.TestCheckResourceAttrSet("clearpass_extension_instance_config.test_cfg", "instance_id"),
					resource.TestCheckResourceAttrSet("clearpass_extension_instance_config.test_cfg", "config_json"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "clearpass_extension_instance_config.test_cfg",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update testing - change config values
			{
				Config: testAccProviderConfig() + `
resource "clearpass_extension_instance" "cfg_parent" {
  store_id = "com.example.test-extension"
  state    = "stopped"
}

resource "clearpass_extension_instance_config" "test_cfg" {
  instance_id = clearpass_extension_instance.cfg_parent.id
  config_json = jsonencode({
    enabled = false
    level   = "debug"
  })
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("clearpass_extension_instance_config.test_cfg", "config_json"),
				),
			},
		},
	})
}
