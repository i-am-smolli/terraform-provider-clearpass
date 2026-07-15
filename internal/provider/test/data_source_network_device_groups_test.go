package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataSourceNetworkDeviceGroups(t *testing.T) {
	uniqueName := acctest.RandomWithPrefix("tf-acc-ds-ndg")

	config := testAccProviderConfig() + `
resource "clearpass_network_device_group" "test_ndg" {
  name         = "` + uniqueName + `"
  description  = "Test NDG for Data Source"
  group_format = "subnet"
  value        = "10.99.99.0/24"
}

data "clearpass_network_device_groups" "all" {
  depends_on = [clearpass_network_device_group.test_ndg]
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.clearpass_network_device_groups.all", "network_device_groups.#"),
				),
			},
		},
	})
}
