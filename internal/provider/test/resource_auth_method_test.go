package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccAuthMethodResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccProviderConfig() + `
resource "clearpass_auth_method" "test_auth_method" {
  name        = "tf-acc-test-auth-method"
  description = "Terraform Acceptance Test Auth Method"
  method_type = "MAC-AUTH"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "name", "tf-acc-test-auth-method"),
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "description", "Terraform Acceptance Test Auth Method"),
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "method_type", "MAC-AUTH"),
				),
			},
			// ImportState testing
			{
				ResourceName:            "clearpass_auth_method.test_auth_method",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"details"},
			},
			// Update and Read testing
			{
				Config: testAccProviderConfig() + `
resource "clearpass_auth_method" "test_auth_method" {
  name        = "tf-acc-test-auth-method-updated"
  description = "Terraform Acceptance Test Auth Method Updated"
  method_type = "MAC-AUTH"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "name", "tf-acc-test-auth-method-updated"),
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "description", "Terraform Acceptance Test Auth Method Updated"),
				),
			},
		},
	})
}
