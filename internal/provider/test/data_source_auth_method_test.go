package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccAuthMethodDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "clearpass_auth_method" "test_auth_method_ds" {
  name        = "tf-acc-test-auth-method-ds"
  description = "Terraform Acceptance Test Auth Method DS"
  method_type = "MAC-AUTH"
}

data "clearpass_auth_method" "test" {
  id = clearpass_auth_method.test_auth_method_ds.id
}

data "clearpass_auth_methods" "all" {
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"data.clearpass_auth_method.test", "id",
						"clearpass_auth_method.test_auth_method_ds", "id",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_auth_method.test", "name",
						"clearpass_auth_method.test_auth_method_ds", "name",
					),
					// At least one data source should be returned in "all"
					resource.TestCheckResourceAttr("data.clearpass_auth_methods.all", "id", "auth_methods"),
				),
			},
		},
	})
}
