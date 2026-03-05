package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccServiceDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProviderConfig() + `
// Pre-requisite: profile
resource "clearpass_enforcement_profile" "test_prof_ds" {
  name        = "tf-acc-test-svc-ds-prof"
  description = "Profile for Service DS Test"
  type        = "RADIUS"
  action      = "Accept"
  attributes  = [{ type = "Radius:IETF", name = "Filter-Id", value = "Test-Allow" }]
}

// Pre-requisite: policy (must include rules)
resource "clearpass_enforcement_policy" "test_ep_ds" {
  name             = "tf-acc-test-service-ep-ds"
  description      = "Used for acceptance testing"
  enforcement_type = "RADIUS"
  default_enforcement_profile = "[Allow Access Profile]"
  rule_eval_algo   = "first-applicable"
  rules = [
    {
      enforcement_profile_names = [clearpass_enforcement_profile.test_prof_ds.name]
      condition = [{
        type  = "Connection"
        name  = "SSID"
        oper  = "EQUALS"
        value = "Test-SSID"
      }]
    }
  ]
}

// Service to retrieve
resource "clearpass_service" "test_svc_ds" {
  name               = "tf-acc-test-svc-ds"
  description        = "Terraform Acceptance Test Service DS"
  template           = "RADIUS Enforcement ( Generic )"
  enabled            = true
  enforcement_policy = clearpass_enforcement_policy.test_ep_ds.name

  auth_methods = ["[EAP PEAP]"]
  auth_sources = ["[Local User Repository]"]

  match_type = "MATCHES_ANY"
  service_rule = [
    {
      type     = "Connection"
      name     = "AP-Name"
      operator = "EQUALS"
      value    = "test-ap"
    }
  ]
}

data "clearpass_service" "test_by_id" {
  id = clearpass_service.test_svc_ds.id
}

data "clearpass_service" "test_by_name" {
  name = clearpass_service.test_svc_ds.name
}

data "clearpass_services" "all" {
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Test single service by ID
					resource.TestCheckResourceAttrPair(
						"data.clearpass_service.test_by_id", "id",
						"clearpass_service.test_svc_ds", "id",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_service.test_by_id", "name",
						"clearpass_service.test_svc_ds", "name",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_service.test_by_id", "template",
						"clearpass_service.test_svc_ds", "template",
					),

					// Test single service by Name
					resource.TestCheckResourceAttrPair(
						"data.clearpass_service.test_by_name", "id",
						"clearpass_service.test_svc_ds", "id",
					),
					resource.TestCheckResourceAttrPair(
						"data.clearpass_service.test_by_name", "name",
						"clearpass_service.test_svc_ds", "name",
					),

					// Ensure at least one is returned in the list
					resource.TestCheckResourceAttrSet("data.clearpass_services.all", "services.#"),
				),
			},
		},
	})
}
