package provider_test

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccServiceCertResource(t *testing.T) {
	// Read the real PFX file from test/cppm-service.pfx
	pfxBytes, err := os.ReadFile("../../../test/cppm-service.pfx")
	if err != nil {
		t.Fatalf("Failed to read test/cppm-service.pfx: %s", err)
	}
	pfxBase64 := base64.StdEncoding.EncodeToString(pfxBytes)

	// Read the root CA cert that the service cert needs
	caBytes, err := os.ReadFile("../../../test/root-ca.pem")
	if err != nil {
		t.Fatalf("Failed to read test/root-ca.pem: %s", err)
	}
	caContent := strings.ReplaceAll(string(caBytes), "\r\n", "\n")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccProviderConfig() + fmt.Sprintf(`
resource "clearpass_cert_trust_list" "ca" {
  cert_file  = "%s"
  enabled    = true
  cert_usage = ["EAP", "RadSec"]
}

resource "clearpass_service_cert" "test" {
  depends_on         = [clearpass_cert_trust_list.ca]
  pkcs12_file_base64 = "`+pfxBase64+`"
  pkcs12_passphrase  = "123456"
}
`, escapeHCLStringServiceCert(caContent)),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("clearpass_service_cert.test", "id"),
					resource.TestCheckResourceAttrSet("clearpass_service_cert.test", "subject"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "clearpass_service_cert.test",
				ImportState:       true,
				ImportStateVerify: true,
				// Passphrase and file content are not returned by API
				ImportStateVerifyIgnore: []string{"pkcs12_passphrase", "certificate_url", "pkcs12_file_url", "pkcs12_file_base64", "port"},
			},
		},
	})
}

func escapeHCLStringServiceCert(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
