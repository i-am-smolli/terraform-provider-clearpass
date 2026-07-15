package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataSourceNetworkDevices(t *testing.T) {
	uniqueName := acctest.RandomWithPrefix("tf-acc-ds-nad")

	config := testAccProviderConfig() + `
resource "clearpass_network_device" "test" {
  name          = "` + uniqueName + `"
  ip_address    = "10.99.0.1"
  description   = "Test NAD for Data Source"
  radius_secret = "testing123"
  vendor_name   = "Aruba"
}

data "clearpass_network_devices" "all" {
  depends_on = [clearpass_network_device.test]
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.clearpass_network_devices.all", "network_devices.#"),
				),
			},
		},
	})
}
