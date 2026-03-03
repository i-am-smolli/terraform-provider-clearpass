package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCertTrustListDataSource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertTrustListDataSourceConfig(),
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

func testAccCertTrustListDataSourceConfig() string {
	return `
data "clearpass_cert_trust_list" "test" {
  id = 1
}
`
}
