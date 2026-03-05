package provider_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCertTrustListResource(t *testing.T) {
	certContent := loadTestCertResource(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccProviderConfig() + testAccCertTrustListResourceConfig(certContent),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("clearpass_cert_trust_list.test", "id"),
					resource.TestCheckResourceAttr("clearpass_cert_trust_list.test", "enabled", "true"),
					resource.TestCheckResourceAttr("clearpass_cert_trust_list.test", "cert_usage.0", "EAP"),
				),
			},
			// ImportState testing
			{
				ResourceName:            "clearpass_cert_trust_list.test",
				ImportState:             true,
				ImportStateVerifyIgnore: []string{"cert_file"},
			},
		},
	})
}

func testAccCertTrustListResourceConfig(certContent string) string {
	return fmt.Sprintf(`
resource "clearpass_cert_trust_list" "test" {
  cert_file  = "%s"
  enabled    = true
  cert_usage = ["EAP", "RadSec"]
}
`, escapeHCLStringResource(certContent))
}

func loadTestCertResource(t *testing.T) string {
	t.Helper()
	certBytes, err := os.ReadFile("../../../test/root-ca.pem")
	if err != nil {
		t.Fatalf("Failed to read test/root-ca.pem: %s", err)
	}
	return strings.ReplaceAll(string(certBytes), "\r\n", "\n")
}

func escapeHCLStringResource(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
