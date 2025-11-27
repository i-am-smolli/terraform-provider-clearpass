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
				Config: `
resource "clearpass_auth_method" "test_auth_method" {
  name        = "tf-acc-test-auth-method"
  description = "Terraform Acceptance Test Auth Method"
  method_type = "EAP-PEAP"

  details {
    session_timeout = 3600
    allow_fast_reconnect = true
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "name", "tf-acc-test-auth-method"),
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "description", "Terraform Acceptance Test Auth Method"),
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "method_type", "EAP-PEAP"),
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "details.0.session_timeout", "3600"),
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "details.0.allow_fast_reconnect", "true"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "clearpass_auth_method.test_auth_method",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing
			{
				Config: `
resource "clearpass_auth_method" "test_auth_method" {
  name        = "tf-acc-test-auth-method-updated"
  description = "Terraform Acceptance Test Auth Method Updated"
  method_type = "EAP-PEAP"

  details {
    session_timeout = 7200
    allow_fast_reconnect = false
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "name", "tf-acc-test-auth-method-updated"),
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "description", "Terraform Acceptance Test Auth Method Updated"),
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "details.0.session_timeout", "7200"),
					resource.TestCheckResourceAttr("clearpass_auth_method.test_auth_method", "details.0.allow_fast_reconnect", "false"),
				),
			},
		},
	})
}
