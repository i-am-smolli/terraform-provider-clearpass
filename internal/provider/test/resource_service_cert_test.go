package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccServiceCertResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccServiceCertResourceConfig("https://example.com/cert.pem", "https://example.com/key.p12", "secret"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("clearpass_service_cert.test", "id"),
					resource.TestCheckResourceAttr("clearpass_service_cert.test", "certificate_url", "https://example.com/cert.pem"),
					resource.TestCheckResourceAttr("clearpass_service_cert.test", "pkcs12_file_url", "https://example.com/key.p12"),
					resource.TestCheckResourceAttrSet("clearpass_service_cert.test", "subject"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "clearpass_service_cert.test",
				ImportState:       true,
				ImportStateVerify: true,
				// Passphrase is sensitive and not returned by API, so we skip verification
				ImportStateVerifyIgnore: []string{"pkcs12_passphrase", "certificate_url", "pkcs12_file_url"},
			},
		},
	})
}

func testAccServiceCertResourceConfig(certURL, keyURL, passphrase string) string {
	return testAccProviderConfig() + `
resource "clearpass_service_cert" "test" {
  certificate_url   = "` + certURL + `"
  pkcs12_file_url   = "` + keyURL + `"
  pkcs12_passphrase = "` + passphrase + `"
}
`
}
