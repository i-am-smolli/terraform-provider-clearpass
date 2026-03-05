package provider_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCertTrustListDataSource_basic(t *testing.T) {
	certContent := loadTestCert(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderConfig() + testAccCertTrustListDSConfig(certContent),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.clearpass_cert_trust_list.test", "id"),
					resource.TestCheckResourceAttrSet("data.clearpass_cert_trust_list.test", "cert_file"),
					resource.TestCheckResourceAttrSet("data.clearpass_cert_trust_list.test", "enabled"),
					resource.TestCheckResourceAttrSet("data.clearpass_cert_trust_list.test", "cert_usage.#"),
				),
			},
		},
	})
}

func testAccCertTrustListDSConfig(certContent string) string {
	return fmt.Sprintf(`
resource "clearpass_cert_trust_list" "test_ds" {
  cert_file  = "%s"
  enabled    = true
  cert_usage = ["EAP"]
}

data "clearpass_cert_trust_list" "test" {
  id = clearpass_cert_trust_list.test_ds.id
}
`, escapeHCLString(certContent))
}

// loadTestCert reads the root CA certificate from the test directory.
func loadTestCert(t *testing.T) string {
	t.Helper()
	certBytes, err := os.ReadFile("../../../test/root-ca.pem")
	if err != nil {
		t.Fatalf("Failed to read test/root-ca.pem: %s", err)
	}
	// Normalize line endings
	return strings.ReplaceAll(string(certBytes), "\r\n", "\n")
}

// escapeHCLString escapes a string for use inside HCL double-quotes.
func escapeHCLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
