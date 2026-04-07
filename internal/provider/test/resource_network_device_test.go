package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccNetworkDeviceResource tests the full CRUD and Import cycle for clearpass_network_device.
func TestAccNetworkDeviceResource(t *testing.T) {
	uniqueName := acctest.RandomWithPrefix("tf-acc-nad")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// 1. Create — minimal config (name + ip_address)
			{
				Config: testAccProviderConfig() + testAccNetworkDeviceConfig(uniqueName, "10.0.0.1", "Initial NAD"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_network_device.test", "name", uniqueName),
					resource.TestCheckResourceAttr("clearpass_network_device.test", "ip_address", "10.0.0.1"),
					resource.TestCheckResourceAttr("clearpass_network_device.test", "description", "Initial NAD"),
					resource.TestCheckResourceAttrSet("clearpass_network_device.test", "id"),
				),
			},
			// 2. Update — change description and IP
			{
				Config: testAccProviderConfig() + testAccNetworkDeviceConfig(uniqueName, "10.0.0.2", "Updated NAD Description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_network_device.test", "name", uniqueName),
					resource.TestCheckResourceAttr("clearpass_network_device.test", "ip_address", "10.0.0.2"),
					resource.TestCheckResourceAttr("clearpass_network_device.test", "description", "Updated NAD Description"),
				),
			},
			// 3. Import — verify terraform import works
			{
				ResourceName:      "clearpass_network_device.test",
				ImportState:       true,
				ImportStateVerify: true,
				// WriteOnly fields are not returned by the API and cannot be verified
				ImportStateVerifyIgnore: []string{"radius_secret", "tacacs_secret"},
			},
		},
	})
}

// TestAccNetworkDeviceResource_Full tests creation with all nested blocks.
func TestAccNetworkDeviceResource_Full(t *testing.T) {
	uniqueName := acctest.RandomWithPrefix("tf-acc-nad-full")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderConfig() + testAccNetworkDeviceFullConfig(uniqueName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_network_device.test_full", "name", uniqueName),
					resource.TestCheckResourceAttr("clearpass_network_device.test_full", "ip_address", "192.168.1.1"),
					resource.TestCheckResourceAttr("clearpass_network_device.test_full", "vendor_name", "Cisco"),
					resource.TestCheckResourceAttr("clearpass_network_device.test_full", "coa_capable", "true"),
					resource.TestCheckResourceAttr("clearpass_network_device.test_full", "coa_port", "3799"),
					resource.TestCheckResourceAttrSet("clearpass_network_device.test_full", "id"),
				),
			},
		},
	})
}

func testAccNetworkDeviceConfig(name, ip, description string) string {
	return `
resource "clearpass_network_device" "test" {
  name          = "` + name + `"
  ip_address    = "` + ip + `"
  description   = "` + description + `"
  radius_secret = "testing123"
}
`
}

func testAccNetworkDeviceFullConfig(name string) string {
	return `
resource "clearpass_network_device" "test_full" {
  name          = "` + name + `"
  ip_address    = "192.168.1.1"
  description   = "Full test NAD"
  radius_secret = "radius-secret-123"
  tacacs_secret = "tacacs-secret-456"
  vendor_name   = "Cisco"
  coa_capable   = true
  coa_port      = 3799

  cli_config {
    type     = "SSH"
    port     = 22
    username = "admin"
    password = "admin-password"
  }

  onconnect_enforcement {
    enabled = false
    ports   = ""
  }
}
`
}
