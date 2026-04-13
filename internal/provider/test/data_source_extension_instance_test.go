// internal/provider/test/data_source_extension_instance_test.go
package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccExtensionInstanceDataSource tests reading details of a specific ExtensionInstance by ID.
func TestAccExtensionInstanceDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderConfig() + `
resource "clearpass_extension_instance" "test_ext_ds" {
  store_id = "com.example.test-extension"
  state    = "stopped"
  note     = "Data Source Test"
}

data "clearpass_extension_instance" "test_ds_read" {
  id = clearpass_extension_instance.test_ext_ds.id
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.clearpass_extension_instance.test_ds_read", "id"),
					resource.TestCheckResourceAttr("data.clearpass_extension_instance.test_ds_read", "state", "stopped"),
					resource.TestCheckResourceAttr("data.clearpass_extension_instance.test_ds_read", "note", "Data Source Test"),
				),
			},
		},
	})
}
