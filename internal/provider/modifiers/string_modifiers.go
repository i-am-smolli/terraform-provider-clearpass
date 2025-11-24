package modifiers

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// UpperCase ist die Fabrik-Funktion für unseren Modifier.
func UpperCase() planmodifier.String {
	return upperCaseModifier{}
}

// upperCaseModifier implementiert die Logik.
type upperCaseModifier struct{}

func (m upperCaseModifier) Description(ctx context.Context) string {
	return "Converts the string value to uppercase."
}

func (m upperCaseModifier) MarkdownDescription(ctx context.Context) string {
	return "Converts the string value to uppercase."
}

// PlanModifyString wird von Terraform aufgerufen, bevor der Plan erstellt wird.
func (m upperCaseModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Wenn kein Wert da ist, machen wir nichts.
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	// Wir lesen den Wert aus der Config ("and"), machen ihn groß ("AND")
	// und schreiben ihn in den Plan.
	val := req.ConfigValue.ValueString()
	resp.PlanValue = types.StringValue(strings.ToUpper(val))
}
