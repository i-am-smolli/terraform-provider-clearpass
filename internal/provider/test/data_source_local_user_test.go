package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDataSourceLocalUser(t *testing.T) {
	uniqueName := acctest.RandomWithPrefix("tf-acc-ds-local-user")

	config := testAccProviderConfig() + `
resource "clearpass_local_user" "test" {
  user_id   = "` + uniqueName + `"
  username  = "` + uniqueName + `"
  password  = "SecretPassword123!"
  role_name = "[Employee]"
  enabled   = true
}

data "clearpass_local_user" "by_id" {
  id = clearpass_local_user.test.id
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair("data.clearpass_local_user.by_id", "id", "clearpass_local_user.test", "id"),
					resource.TestCheckResourceAttrPair("data.clearpass_local_user.by_id", "user_id", "clearpass_local_user.test", "user_id"),
					resource.TestCheckResourceAttrPair("data.clearpass_local_user.by_id", "username", "clearpass_local_user.test", "username"),
					resource.TestCheckResourceAttrPair("data.clearpass_local_user.by_id", "role_name", "clearpass_local_user.test", "role_name"),
					resource.TestCheckResourceAttrPair("data.clearpass_local_user.by_id", "enabled", "clearpass_local_user.test", "enabled"),
				),
			},
		},
	})
}
