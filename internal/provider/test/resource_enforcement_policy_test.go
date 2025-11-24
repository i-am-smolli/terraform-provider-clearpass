// internal/provider/resource_enforcement_policy_test.go
package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccEnforcementPolicyResource(t *testing.T) {
	// Generate a unique name prefix
	namePrefix := acctest.RandomWithPrefix("tf-acc-policy")
	profileName := namePrefix + "-prof"
	policyName := namePrefix + "-pol"

	// Config 1: Initial Creation (SSID = "Corporate-A")
	config1 := testAccProviderConfig() + testAccEnforcementPolicyConfig(policyName, profileName, "Initial Policy", "Corporate-A")

	// Config 2: Update (Description changed, SSID = "Corporate-B")
	config2 := testAccProviderConfig() + testAccEnforcementPolicyConfig(policyName, profileName, "Updated Policy Description", "Corporate-B")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// 1. CREATE
			{
				Config: config1,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check basic fields
					resource.TestCheckResourceAttr("clearpass_enforcement_policy.test_policy", "name", policyName),
					resource.TestCheckResourceAttr("clearpass_enforcement_policy.test_policy", "description", "Initial Policy"),
					resource.TestCheckResourceAttr("clearpass_enforcement_policy.test_policy", "default_enforcement_profile", "[Deny Access Profile]"),

					// Check Nested Rules
					resource.TestCheckResourceAttr("clearpass_enforcement_policy.test_policy", "rules.#", "1"),
					// Check that the rule references our created profile
					resource.TestCheckResourceAttr("clearpass_enforcement_policy.test_policy", "rules.0.enforcement_profile_names.0", profileName),
					// Check the condition value
					resource.TestCheckResourceAttr("clearpass_enforcement_policy.test_policy", "rules.0.condition.0.value", "Corporate-A"),

					resource.TestCheckResourceAttrSet("clearpass_enforcement_policy.test_policy", "id"),
				),
			},
			// 2. UPDATE
			{
				Config: config2,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("clearpass_enforcement_policy.test_policy", "description", "Updated Policy Description"),
					// Verify the condition updated
					resource.TestCheckResourceAttr("clearpass_enforcement_policy.test_policy", "rules.0.condition.0.value", "Corporate-B"),
				),
			},
			// 3. IMPORT
			{
				ResourceName:      "clearpass_enforcement_policy.test_policy",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// Helper to generate the HCL.
// Note: We create the dependent 'clearpass_enforcement_profile' here too.
func testAccEnforcementPolicyConfig(policyName, profileName, description, ssid string) string {
	return `
# 1. Dependency: Create a Profile first
resource "clearpass_enforcement_profile" "dep_profile" {
  name        = "` + profileName + `"
  description = "Dependency for Policy Test"
  type        = "RADIUS"
  action      = "Accept"
  attributes  = [{ type = "Radius:IETF", name = "Filter-Id", value = "Test-Allow" }]
}

# 2. The Policy using that Profile
resource "clearpass_enforcement_policy" "test_policy" {
  name                        = "` + policyName + `"
  description                 = "` + description + `"
  enforcement_type            = "RADIUS"
  default_enforcement_profile = "[Deny Access Profile]"
  rule_eval_algo              = "first-applicable"

  rules = [
    {
      # Reference the profile by name
      enforcement_profile_names = [clearpass_enforcement_profile.dep_profile.name]

      condition = [{
        type  = "Connection"
        name  = "SSID"
        oper  = "EQUALS"
        value = "` + ssid + `"
      }]
    }
  ]
}
`
}
