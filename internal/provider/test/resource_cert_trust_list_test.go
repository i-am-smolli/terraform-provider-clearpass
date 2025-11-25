package provider_test

import (
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCertTrustListResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccCertTrustListResourceConfig("dummy_cert_content", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("clearpass_cert_trust_list.test", "id"),
					resource.TestCheckResourceAttr("clearpass_cert_trust_list.test", "cert_file", "dummy_cert_content"),
					resource.TestCheckResourceAttr("clearpass_cert_trust_list.test", "enabled", "true"),
					resource.TestCheckResourceAttr("clearpass_cert_trust_list.test", "cert_usage.0", "EAP"),
				),
			},
			// Update testing
			{
				Config: testAccCertTrustListResourceConfig("updated_cert_content", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_cert_trust_list.test", "cert_file", "updated_cert_content"),
					resource.TestCheckResourceAttr("clearpass_cert_trust_list.test", "enabled", "false"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "clearpass_cert_trust_list.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCertTrustListResourceConfig(certFile string, enabled bool) string {
	return `
resource "clearpass_cert_trust_list" "test" {
  cert_file = "` + certFile + `"
  enabled   = ` + strconv.FormatBool(enabled) + `
  cert_usage = ["EAP", "RadSec"]
}
`
}
