package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccCertTrustListsDataSource_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCertTrustListsDataSourceConfig(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.clearpass_cert_trust_lists.test", "lists.#"),
				),
			},
		},
	})
}

func testAccCertTrustListsDataSourceConfig() string {
	return testAccProviderConfig() + `
data "clearpass_cert_trust_lists" "test" {}
`
}
