// internal/provider/modifiers/string_modifiers_test.go
package modifiers_test

import (
	"context"
	"testing"

	"terraform-provider-clearpass/internal/provider/modifiers"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestUpperCaseModifier(t *testing.T) {
	tests := []struct {
		name   string
		config types.String
		expect types.String
	}{
		{"config_value_is_lowercase", types.StringValue("and"), types.StringValue("AND")},
		{"config_value_is_mixed_case", types.StringValue("oR"), types.StringValue("OR")},
		{"config_value_is_uppercase", types.StringValue("AND"), types.StringValue("AND")},
		{"config_value_is_null", types.StringNull(), types.StringNull()},
		{"config_value_is_unknown", types.StringUnknown(), types.StringNull()},
	}

	modifier := modifiers.UpperCase()
	ctx := context.Background()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			planVal := tc.config
			resp := &planmodifier.StringResponse{}
			modifier.PlanModifyString(ctx, planmodifier.StringRequest{
				ConfigValue: tc.config,
				PlanValue:   planVal,
			}, resp)
			if !tc.expect.Equal(resp.PlanValue) {
				t.Errorf("expected plan value %v, got %v", tc.expect, resp.PlanValue)
			}
		})
	}
}
