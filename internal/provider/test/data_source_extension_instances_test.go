// internal/provider/test/data_source_extension_instances_test.go
package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccExtensionInstancesDataSource tests reading a list of all ExtensionInstances.
func TestAccExtensionInstancesDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderConfig() + `
data "clearpass_extension_instances" "all_exts" {
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.clearpass_extension_instances.all_exts", "instances"),
				),
			},
		},
	})
}
