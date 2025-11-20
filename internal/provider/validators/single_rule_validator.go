package validators

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type ruleValidationModel struct {
	MatchType types.String `tfsdk:"match_type"`
	RoleName  types.String `tfsdk:"role_name"`
	Condition types.List   `tfsdk:"condition"`
}

// singleConditionMustBeOrValidator implementation
// singleConditionMustBeOrValidator implements the validation logic.
type singleConditionMustBeOrValidator struct{}

// Description
func (v singleConditionMustBeOrValidator) Description(ctx context.Context) string {
	return "Validates that if a rule has only one condition, match_type must be 'or'."
}

func (v singleConditionMustBeOrValidator) MarkdownDescription(ctx context.Context) string {
	return "Due to a ClearPass API behavior, if a rule contains exactly **one condition**, the `match_type` is automatically normalized to `or`. To prevent permanent diffs, this validator enforces `or` when only one condition is present."
}

// ValidateList performs the validation
func (v singleConditionMustBeOrValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	// 1. If the rule list is empty, everything is okay
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	// 2. Load all rules into our helper struct
	var rules []ruleValidationModel
	diags := req.ConfigValue.ElementsAs(ctx, &rules, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// 3. Iterate through EACH rule
	for i, rule := range rules {
		// If conditions are unknown or null, skip
		if rule.Condition.IsUnknown() || rule.Condition.IsNull() {
			continue
		}

		// We don't need to know what's IN the condition,
		// we just need to know HOW MANY there are.
		// Since 'ElementsAs' can be expensive, we just get the length of the list.
		conditionCount := len(rule.Condition.Elements())

		// 4. THE CHECK: Exactly 1 condition AND MatchType is "and"
		if conditionCount == 1 && rule.MatchType.ValueString() == "AND" {
			resp.Diagnostics.AddAttributeError(
				req.Path, // Points to the 'rules' list
				fmt.Sprintf("Invalid 'match_type' in rule #%d", i+1),
				"Due to a ClearPass API bug, `match_type` must be \"OR\" when a rule has exactly one condition. Please change it to \"OR\".",
			)
		}
	}
}

// SingleRuleMustBeOr factory function (keep the name so we don't have to change provider.go)
func SingleRuleMustBeOr() validator.List {
	return singleConditionMustBeOrValidator{}
}
