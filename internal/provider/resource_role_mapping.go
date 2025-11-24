// internal/provider/resource_role_mapping.go
package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"terraform-provider-clearpass/internal/client"
	"terraform-provider-clearpass/internal/provider/modifiers"
	"terraform-provider-clearpass/internal/provider/validators"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider-defined types implement framework interfaces.
var _ resource.Resource = &roleMappingResource{}

// roleMappingResource defines the resource implementation.
type roleMappingResource struct {
	client client.ClientInterface
}

// --- Data Models ---

// These structs define the HCL shape (the "tfsdk" tags).
type roleMappingResourceModel struct {
	ID              types.Int64  `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	DefaultRoleName types.String `tfsdk:"default_role_name"`
	RuleCombineAlgo types.String `tfsdk:"rule_combine_algo"`
	Rules           types.List   `tfsdk:"rules"` // List of rulesModel
}

type rulesModel struct {
	MatchType types.String `tfsdk:"match_type"`
	RoleName  types.String `tfsdk:"role_name"`
	Condition types.List   `tfsdk:"condition"` // List of conditionModel
}

type conditionModel struct {
	Type  types.String `tfsdk:"type"`
	Name  types.String `tfsdk:"name"`
	Oper  types.String `tfsdk:"oper"`
	Value types.String `tfsdk:"value"`
}

// --- Resource Implementation ---

// NewRoleMappingResource is a factory function for the resource.
func NewRoleMappingResource() resource.Resource {
	return &roleMappingResource{}
}

// Metadata returns the resource type name.
func (r *roleMappingResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role_mapping"
}

// Schema defines the HCL attributes for the resource.
func (r *roleMappingResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Role Mapping Policy.",

		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Numeric ID of the role mapping.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Role mapping policy name.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Role mapping description.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"default_role_name": schema.StringAttribute{
				Description: "Role mapping default role name (e.g., '[Guest]').",
				Required:    true,
			},
			"rule_combine_algo": schema.StringAttribute{
				Description: "Rules evaluation algorithm ('first-applicable' or 'evaluate-all').",
				Required:    true,
			},
			"rules": schema.ListNestedAttribute{
				Description: "List of role mapping rules.",
				Required:    true,
				Validators: []validator.List{
					validators.SingleRuleMustBeOr(),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"match_type": schema.StringAttribute{
							Description: "Matches ANY ('OR') or ALL ('ALL') of the conditions.",
							Required:    true,
							PlanModifiers: []planmodifier.String{
								modifiers.UpperCase(),
							},
							Validators: []validator.String{
								// HPE messed up the API. Sorry, I need to enforce this here.
								stringvalidator.OneOf("AND", "OR"),
							},
						},
						"role_name": schema.StringAttribute{
							Description: "The role to assign if the conditions match.",
							Required:    true,
						},
						"condition": schema.ListNestedAttribute{
							Description: "List of conditions for this rule.",
							Required:    true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										Description: "Condition type (e.g., 'Authentication', 'Connection').",
										Required:    true,
									},
									"name": schema.StringAttribute{
										Description: "Condition name (e.g., 'Status', 'SSID').",
										Required:    true,
									},
									"oper": schema.StringAttribute{
										Description: "Condition operator (e.g., 'EQUALS', 'NOT_EQUALS').",
										Required:    true,
									},
									"value": schema.StringAttribute{
										Description: "Condition value to match.",
										Required:    true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// Configure passes the API client to the resource.
func (r *roleMappingResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected client.ClientInterface, got: %T.", req.ProviderData))
		return
	}
	r.client = client
}

// Create is called when the resource is created.
func (r *roleMappingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleMappingResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// === TRANSLATE: HCL Model -> API Client Model ===
	apiPayload := &client.RoleMappingCreate{
		Name:            plan.Name.ValueString(),
		DefaultRoleName: plan.DefaultRoleName.ValueString(),
		RuleCombineAlgo: plan.RuleCombineAlgo.ValueString(),
		Rules:           expandRoleMappingRules(ctx, plan.Rules, &resp.Diagnostics),
	}
	if !plan.Description.IsNull() {
		apiPayload.Description = plan.Description.ValueString()
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// === API CALL ===
	createdRoleMap, err := r.client.CreateRoleMapping(ctx, apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to create role mapping: %s", err))
		return
	}

	// === TRANSLATE: API Result -> HCL State ===
	var diags diag.Diagnostics
	plan.ID = types.Int64Value(int64(createdRoleMap.ID))
	plan.Name = types.StringValue(createdRoleMap.Name)
	plan.Description = types.StringValue(createdRoleMap.Description)
	plan.DefaultRoleName = types.StringValue(createdRoleMap.DefaultRoleName)
	plan.RuleCombineAlgo = types.StringValue(createdRoleMap.RuleCombineAlgo)
	plan.Rules, diags = flattenRoleMappingRules(ctx, createdRoleMap.Rules)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read is called to refresh the resource state.
func (r *roleMappingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleMappingResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	numericID := state.ID.ValueInt64()
	roleMap, err := r.client.GetRoleMapping(ctx, int(numericID))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to read role mapping: %s", err))
		return
	}

	if roleMap == nil {
		resp.Diagnostics.AddWarning("Resource Not Found", "Role mapping not found, removing from state.")
		resp.State.RemoveResource(ctx)
		return
	}

	// === TRANSLATE: API Result -> HCL State ===
	var diags diag.Diagnostics
	state.ID = types.Int64Value(int64(roleMap.ID))
	state.Name = types.StringValue(roleMap.Name)
	state.Description = types.StringValue(roleMap.Description)
	state.DefaultRoleName = types.StringValue(roleMap.DefaultRoleName)
	state.RuleCombineAlgo = types.StringValue(roleMap.RuleCombineAlgo)
	state.Rules, diags = flattenRoleMappingRules(ctx, roleMap.Rules)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is called when the resource is updated.
func (r *roleMappingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan roleMappingResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// === TRANSLATE: HCL Plan -> API Client Model ===
	apiPayload := &client.RoleMappingUpdate{
		Rules: expandRoleMappingRulesUpdate(ctx, plan.Rules, &resp.Diagnostics),
	}
	if !plan.Name.IsUnknown() {
		apiPayload.Name = plan.Name.ValueString()
	}
	if !plan.Description.IsUnknown() {
		apiPayload.Description = plan.Description.ValueString()
	}
	if !plan.DefaultRoleName.IsUnknown() {
		apiPayload.DefaultRoleName = plan.DefaultRoleName.ValueString()
	}
	if !plan.RuleCombineAlgo.IsUnknown() {
		apiPayload.RuleCombineAlgo = plan.RuleCombineAlgo.ValueString()
	}
	if resp.Diagnostics.HasError() {
		return
	}

	numericID := plan.ID.ValueInt64()
	updatedRoleMap, err := r.client.UpdateRoleMapping(ctx, int(numericID), apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to update role mapping: %s", err))
		return
	}

	// === TRANSLATE: API Result -> HCL State ===
	var diags diag.Diagnostics
	plan.ID = types.Int64Value(int64(updatedRoleMap.ID))
	plan.Name = types.StringValue(updatedRoleMap.Name)
	plan.Description = types.StringValue(updatedRoleMap.Description)
	plan.DefaultRoleName = types.StringValue(updatedRoleMap.DefaultRoleName)
	plan.RuleCombineAlgo = types.StringValue(updatedRoleMap.RuleCombineAlgo)
	plan.Rules, diags = flattenRoleMappingRules(ctx, updatedRoleMap.Rules)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete is called when the resource is destroyed.
func (r *roleMappingResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleMappingResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	numericID := state.ID.ValueInt64()
	err := r.client.DeleteRoleMapping(ctx, int(numericID))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to delete role mapping with ID %d: %s", numericID, err))
		return
	}
}

// --- Translation Helpers ---

// expandRoleMappingRules converts Terraform List model to API client slice for Create.
func expandRoleMappingRules(ctx context.Context, tfList types.List, diags *diag.Diagnostics) []*client.RulesSettingsCreate {
	if tfList.IsNull() {
		return nil
	}
	var apiRules []*client.RulesSettingsCreate

	// Get the elements from the Terraform list
	var tfRules []rulesModel
	diags.Append(tfList.ElementsAs(ctx, &tfRules, false)...)
	if diags.HasError() {
		return nil
	}

	for _, tfRule := range tfRules {
		apiRule := &client.RulesSettingsCreate{
			MatchType: tfRule.MatchType.ValueString(),
			RoleName:  tfRule.RoleName.ValueString(),
		}

		// Expand inner conditions
		if !tfRule.Condition.IsNull() {
			var tfConditions []conditionModel
			diags.Append(tfRule.Condition.ElementsAs(ctx, &tfConditions, false)...)
			if diags.HasError() {
				return nil
			}

			for _, tfCond := range tfConditions {
				apiRule.Condition = append(apiRule.Condition, &client.RulesConditionSettingsCreate{
					Type:  tfCond.Type.ValueString(),
					Name:  tfCond.Name.ValueString(),
					Oper:  tfCond.Oper.ValueString(),
					Value: tfCond.Value.ValueString(),
				})
			}
		}
		apiRules = append(apiRules, apiRule)
	}
	return apiRules
}

// expandRoleMappingRulesUpdate converts Terraform List model to API client slice for Update.
func expandRoleMappingRulesUpdate(ctx context.Context, tfList types.List, diags *diag.Diagnostics) []*client.RulesSettingsUpdate {
	if tfList.IsNull() {
		return nil
	}
	var apiRules []*client.RulesSettingsUpdate

	var tfRules []rulesModel
	diags.Append(tfList.ElementsAs(ctx, &tfRules, false)...)
	if diags.HasError() {
		return nil
	}

	for _, tfRule := range tfRules {
		apiRule := &client.RulesSettingsUpdate{
			MatchType: tfRule.MatchType.ValueString(),
			RoleName:  tfRule.RoleName.ValueString(),
		}

		if !tfRule.Condition.IsNull() {
			var tfConditions []conditionModel
			diags.Append(tfRule.Condition.ElementsAs(ctx, &tfConditions, false)...)
			if diags.HasError() {
				return nil
			}

			for _, tfCond := range tfConditions {
				apiRule.Condition = append(apiRule.Condition, &client.RulesConditionSettingsUpdate{
					Type:  tfCond.Type.ValueString(),
					Name:  tfCond.Name.ValueString(),
					Oper:  tfCond.Oper.ValueString(),
					Value: tfCond.Value.ValueString(),
				})
			}
		}
		apiRules = append(apiRules, apiRule)
	}
	return apiRules
}

// flattenRoleMappingRules converts API client slice to Terraform List model.
func flattenRoleMappingRules(ctx context.Context, apiRules []*client.RulesSettingsResult) (types.List, diag.Diagnostics) {
	if apiRules == nil {
		return types.ListNull(types.ObjectType{AttrTypes: rulesModel{}.attrTypes()}), nil
	}

	var tfRules []rulesModel
	for _, apiRule := range apiRules {

		// Flatten inner conditions first
		var tfConditions []conditionModel
		for _, apiCond := range apiRule.Condition {
			tfConditions = append(tfConditions, conditionModel{
				Type:  types.StringValue(apiCond.Type),
				Name:  types.StringValue(apiCond.Name),
				Oper:  types.StringValue(apiCond.Oper),
				Value: types.StringValue(apiCond.Value),
			})
		}

		condList, diags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: conditionModel{}.attrTypes()}, tfConditions)
		if diags.HasError() {
			return types.ListNull(types.ObjectType{AttrTypes: rulesModel{}.attrTypes()}), diags
		}

		tfRules = append(tfRules, rulesModel{
			// We force the API value to Uppercase ("and" -> "AND", "OR" -> "OR")
			MatchType: types.StringValue(strings.ToUpper(apiRule.MatchType)),
			RoleName:  types.StringValue(apiRule.RoleName),
			Condition: condList,
		})
	}

	rulesList, diags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: rulesModel{}.attrTypes()}, tfRules)
	return rulesList, diags
}

// These are helpers for the helpers, to define the 'shape' of our nested objects.
func (m rulesModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"match_type": types.StringType,
		"role_name":  types.StringType,
		"condition": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: conditionModel{}.attrTypes(),
			},
		},
	}
}

func (m conditionModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type":  types.StringType,
		"name":  types.StringType,
		"oper":  types.StringType,
		"value": types.StringType,
	}
}

func (r *roleMappingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	numericID, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected a numeric ID for import, got %q. Error: %s", req.ID, err.Error()),
		)
		return
	}

	// The framework requires us to set the 'id' field in the state.
	// The subsequent Read function will use this ID to fetch the full state.
	resp.Diagnostics.Append(resp.State.SetAttribute(
		ctx,
		path.Root("id"),
		numericID,
	)...)
}
