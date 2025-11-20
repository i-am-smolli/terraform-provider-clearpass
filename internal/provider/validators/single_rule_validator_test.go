// internal/provider/validators/single_rule_validator_test.go
package validators_test

import (
	"context"
	"strings"
	"testing"

	"terraform-provider-clearpass/internal/provider/validators"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type conditionModel struct {
	Type  types.String `tfsdk:"type"`
	Name  types.String `tfsdk:"name"`
	Oper  types.String `tfsdk:"oper"`
	Value types.String `tfsdk:"value"`
}

type ruleModel struct {
	MatchType types.String `tfsdk:"match_type"`
	RoleName  types.String `tfsdk:"role_name"`
	Condition types.List   `tfsdk:"condition"`
}

func (m conditionModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type": types.StringType, "name": types.StringType, "oper": types.StringType, "value": types.StringType,
	}
}

func (m ruleModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"match_type": types.StringType,
		"role_name":  types.StringType,
		"condition": types.ListType{
			ElemType: types.ObjectType{AttrTypes: conditionModel{}.attrTypes()},
		},
	}
}

func TestSingleRuleMustBeOr(t *testing.T) {
	ctx := context.Background()

	validCondition, _ := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: conditionModel{}.attrTypes()}, []attr.Value{
		types.ObjectValueMust(conditionModel{}.attrTypes(), map[string]attr.Value{
			"type":  types.StringValue("Connection"),
			"name":  types.StringValue("SSID"),
			"oper":  types.StringValue("EQUALS"),
			"value": types.StringValue("WiFi"),
		}),
	})
	twoConditions, _ := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: conditionModel{}.attrTypes()}, []attr.Value{
		types.ObjectValueMust(conditionModel{}.attrTypes(), map[string]attr.Value{
			"type": types.StringValue("C1"), "name": types.StringValue("N1"), "oper": types.StringValue("E1"), "value": types.StringValue("V1"),
		}),
		types.ObjectValueMust(conditionModel{}.attrTypes(), map[string]attr.Value{
			"type": types.StringValue("C2"), "name": types.StringValue("N2"), "oper": types.StringValue("E2"), "value": types.StringValue("V2"),
		}),
	})

	ruleType := types.ObjectType{AttrTypes: ruleModel{}.attrTypes()}

	tests := []struct {
		name        string
		rules       []attr.Value
		expectError bool
		errorMsg    string
	}{
		{
			name: "pass_two_rules",
			rules: []attr.Value{
				types.ObjectValueMust(ruleModel{}.attrTypes(), map[string]attr.Value{
					"match_type": types.StringValue("AND"),
					"role_name":  types.StringValue("[Guest]"),
					"condition":  twoConditions,
				}),
				types.ObjectValueMust(ruleModel{}.attrTypes(), map[string]attr.Value{
					"match_type": types.StringValue("OR"),
					"role_name":  types.StringValue("[Employee]"),
					"condition":  twoConditions,
				}),
			},
			expectError: false,
		},
		{
			name: "pass_one_rule_is_or",
			rules: []attr.Value{
				types.ObjectValueMust(ruleModel{}.attrTypes(), map[string]attr.Value{
					"match_type": types.StringValue("OR"),
					"role_name":  types.StringValue("[Employee]"),
					"condition":  validCondition,
				}),
			},
			expectError: false,
		},
		{
			name: "fail_one_rule_is_and",
			rules: []attr.Value{
				types.ObjectValueMust(ruleModel{}.attrTypes(), map[string]attr.Value{
					"match_type": types.StringValue("AND"),
					"role_name":  types.StringValue("[Guest]"),
					"condition":  validCondition,
				}),
			},
			expectError: true,
			errorMsg:    "Due to a ClearPass API bug",
		},
		{
			name:        "pass_empty_rules",
			rules:       []attr.Value{},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listVal := types.ListValueMust(ruleType, tc.rules)
			v := validators.SingleRuleMustBeOr()
			resp := &validator.ListResponse{}
			v.ValidateList(ctx, validator.ListRequest{
				Path:        path.Root("rules"),
				ConfigValue: listVal,
			}, resp)
			if tc.expectError {
				found := false
				for _, d := range resp.Diagnostics {
					if d.Severity() == diag.SeverityError &&
						(strings.Contains(d.Summary(), tc.errorMsg) || strings.Contains(d.Detail(), tc.errorMsg)) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error containing %q, got diagnostics: %v", tc.errorMsg, resp.Diagnostics)
				}
			} else {
				for _, d := range resp.Diagnostics {
					if d.Severity() == diag.SeverityError {
						t.Errorf("unexpected error: %v", d.Summary())
					}
				}
			}
		})
	}
}
