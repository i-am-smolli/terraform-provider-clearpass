// internal/provider/test/resource_network_device_group_test.go
package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccNetworkDeviceGroupResource tests the full CRUD and Import cycle for clearpass_network_device_group.
func TestAccNetworkDeviceGroupResource(t *testing.T) {
	uniqueName := acctest.RandomWithPrefix("tf-acc-ndg")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// 1. Create - Test initial creation with subnet format
			{
				Config: testAccProviderConfig() + testAccNetworkDeviceGroupConfig(uniqueName, "Initial NDG description", "subnet", "10.0.0.0/8"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_network_device_group.test_ndg", "name", uniqueName),
					resource.TestCheckResourceAttr("clearpass_network_device_group.test_ndg", "description", "Initial NDG description"),
					resource.TestCheckResourceAttr("clearpass_network_device_group.test_ndg", "group_format", "subnet"),
					resource.TestCheckResourceAttr("clearpass_network_device_group.test_ndg", "value", "10.0.0.0/8"),
					resource.TestCheckResourceAttrSet("clearpass_network_device_group.test_ndg", "id"),
				),
			},
			// 2. Update - Change description and value
			{
				Config: testAccProviderConfig() + testAccNetworkDeviceGroupConfig(uniqueName, "Updated NDG description", "subnet", "192.168.0.0/16"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_network_device_group.test_ndg", "name", uniqueName),
					resource.TestCheckResourceAttr("clearpass_network_device_group.test_ndg", "description", "Updated NDG description"),
					resource.TestCheckResourceAttr("clearpass_network_device_group.test_ndg", "group_format", "subnet"),
					resource.TestCheckResourceAttr("clearpass_network_device_group.test_ndg", "value", "192.168.0.0/16"),
				),
			},
			// 3. Import State - Test 'terraform import' functionality
			{
				ResourceName:      "clearpass_network_device_group.test_ndg",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// HCL configuration helper function.
func testAccNetworkDeviceGroupConfig(name, description, groupFormat, value string) string {
	return `
resource "clearpass_network_device_group" "test_ndg" {
  name         = "` + name + `"
  description  = "` + description + `"
  group_format = "` + groupFormat + `"
  value        = "` + value + `"
}
`
}
