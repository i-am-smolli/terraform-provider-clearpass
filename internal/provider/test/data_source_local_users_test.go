package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataSourceLocalUsers(t *testing.T) {
	uniqueName := acctest.RandomWithPrefix("tf-acc-ds-local-users")

	config := testAccProviderConfig() + `
resource "clearpass_local_user" "test" {
  user_id   = "` + uniqueName + `"
  username  = "` + uniqueName + `"
  password  = "SecretPassword123!"
  role_name = "[Employee]"
  enabled   = true
}

data "clearpass_local_users" "all" {
  depends_on = [clearpass_local_user.test]
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.clearpass_local_users.all", "id"),
					resource.TestCheckResourceAttrSet("data.clearpass_local_users.all", "items.#"),
				),
			},
		},
	})
}
