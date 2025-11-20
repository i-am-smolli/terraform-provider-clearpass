package provider

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

var _ resource.Resource = &enforcementPolicyResource{}

type enforcementPolicyResource struct {
	client client.ClientInterface
}

// --- Data Models ---

type enforcementPolicyModel struct {
	ID                        types.Int64  `tfsdk:"id"`
	Name                      types.String `tfsdk:"name"`
	Description               types.String `tfsdk:"description"`
	EnforcementType           types.String `tfsdk:"enforcement_type"`
	DefaultEnforcementProfile types.String `tfsdk:"default_enforcement_profile"`
	RuleEvalAlgo              types.String `tfsdk:"rule_eval_algo"`
	Rules                     types.List   `tfsdk:"rules"` // List of policyRuleModel
}

type policyRuleModel struct {
	EnforcementProfileNames types.List `tfsdk:"enforcement_profile_names"` // List of strings
	Condition               types.List `tfsdk:"condition"`                 // List of policyConditionModel
}

type policyConditionModel struct {
	Type  types.String `tfsdk:"type"`
	Name  types.String `tfsdk:"name"`
	Oper  types.String `tfsdk:"oper"`
	Value types.String `tfsdk:"value"`
}

// --- Resource Implementation ---

func NewEnforcementPolicyResource() resource.Resource {
	return &enforcementPolicyResource{}
}

func (r *enforcementPolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_enforcement_policy"
}

func (r *enforcementPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an Enforcement Policy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description:   "Numeric ID of the policy.",
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Description: "Name of the policy.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description:   "Description of the policy.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"enforcement_type": schema.StringAttribute{
				Description: "Type (RADIUS, TACACS, WEBAUTH, etc.).",
				Required:    true,
			},
			"default_enforcement_profile": schema.StringAttribute{
				Description: "Name of the default profile to apply if no rules match.",
				Required:    true,
			},
			"rule_eval_algo": schema.StringAttribute{
				Description: "Algorithm ('first-applicable', 'evaluate-all').",
				Required:    true,
			},
			"rules": schema.ListNestedAttribute{
				Description: "List of enforcement rules.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"enforcement_profile_names": schema.ListAttribute{
							Description: "List of profile names to apply.",
							Required:    true,
							ElementType: types.StringType,
						},
						"condition": schema.ListNestedAttribute{
							Description: "List of conditions for this rule.",
							Required:    true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{Required: true},
									"name": schema.StringAttribute{Required: true},
									"oper": schema.StringAttribute{Required: true},
									"value": schema.StringAttribute{Required: true},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *enforcementPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil { return }
	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Type", fmt.Sprintf("Expected ClientInterface, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

func (r *enforcementPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan enforcementPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() { return }

	apiPayload := &client.EnforcementPolicyCreate{
		Name:                      plan.Name.ValueString(),
		EnforcementType:           plan.EnforcementType.ValueString(),
		DefaultEnforcementProfile: plan.DefaultEnforcementProfile.ValueString(),
		RuleEvalAlgo:              plan.RuleEvalAlgo.ValueString(),
		Rules:                     expandPolicyRules(ctx, plan.Rules, &resp.Diagnostics),
	}
	if !plan.Description.IsNull() { apiPayload.Description = plan.Description.ValueString() }
	
	if resp.Diagnostics.HasError() { return }

	created, err := r.client.CreateEnforcementPolicy(ctx, apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
		return
	}

	// Map back
	plan.ID = types.Int64Value(int64(created.ID))
	plan.Name = types.StringValue(created.Name)
	plan.Description = types.StringValue(created.Description)
	plan.EnforcementType = types.StringValue(created.EnforcementType)
	plan.DefaultEnforcementProfile = types.StringValue(created.DefaultEnforcementProfile)
	plan.RuleEvalAlgo = types.StringValue(created.RuleEvalAlgo)
	
	var diags diag.Diagnostics
	plan.Rules, diags = flattenPolicyRules(ctx, created.Rules)
	resp.Diagnostics.Append(diags...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *enforcementPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state enforcementPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() { return }

	policy, err := r.client.GetEnforcementPolicy(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
		return
	}
	if policy == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.Name = types.StringValue(policy.Name)
	state.Description = types.StringValue(policy.Description)
	state.EnforcementType = types.StringValue(policy.EnforcementType)
	state.DefaultEnforcementProfile = types.StringValue(policy.DefaultEnforcementProfile)
	state.RuleEvalAlgo = types.StringValue(policy.RuleEvalAlgo)
	
	var diags diag.Diagnostics
	state.Rules, diags = flattenPolicyRules(ctx, policy.Rules)
	resp.Diagnostics.Append(diags...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *enforcementPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan enforcementPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() { return }

	apiPayload := &client.EnforcementPolicyUpdate{
		Rules: expandPolicyRulesUpdate(ctx, plan.Rules, &resp.Diagnostics),
	}
	if !plan.Name.IsUnknown() { apiPayload.Name = plan.Name.ValueString() }
	if !plan.Description.IsUnknown() { apiPayload.Description = plan.Description.ValueString() }
	if !plan.EnforcementType.IsUnknown() { apiPayload.EnforcementType = plan.EnforcementType.ValueString() }
	if !plan.DefaultEnforcementProfile.IsUnknown() { apiPayload.DefaultEnforcementProfile = plan.DefaultEnforcementProfile.ValueString() }
	if !plan.RuleEvalAlgo.IsUnknown() { apiPayload.RuleEvalAlgo = plan.RuleEvalAlgo.ValueString() }

	if resp.Diagnostics.HasError() { return }

	updated, err := r.client.UpdateEnforcementPolicy(ctx, int(plan.ID.ValueInt64()), apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
		return
	}
	
	// Refresh state
	plan.Name = types.StringValue(updated.Name)
	plan.Description = types.StringValue(updated.Description)
	plan.EnforcementType = types.StringValue(updated.EnforcementType)
	plan.DefaultEnforcementProfile = types.StringValue(updated.DefaultEnforcementProfile)
	plan.RuleEvalAlgo = types.StringValue(updated.RuleEvalAlgo)
	
	var diags diag.Diagnostics
	plan.Rules, diags = flattenPolicyRules(ctx, updated.Rules)
	resp.Diagnostics.Append(diags...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *enforcementPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state enforcementPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() { return }
	err := r.client.DeleteEnforcementPolicy(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
	}
}

func (r *enforcementPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	numericID, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", fmt.Sprintf("Expected numeric ID, got %q", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), numericID)...)
}

// --- Helpers ---

func expandPolicyRules(ctx context.Context, list types.List, diags *diag.Diagnostics) []*client.EnforcementPolicyRuleCreate {
	if list.IsNull() || list.IsUnknown() { return nil }
	var tfRules []policyRuleModel
	diags.Append(list.ElementsAs(ctx, &tfRules, false)...)
	if diags.HasError() { return nil }

	var apiRules []*client.EnforcementPolicyRuleCreate
	for _, item := range tfRules {
		var profiles []string
		diags.Append(item.EnforcementProfileNames.ElementsAs(ctx, &profiles, false)...)
		
		var conditions []*client.EnforcementPolicyConditionCreate
		var tfConds []policyConditionModel
		diags.Append(item.Condition.ElementsAs(ctx, &tfConds, false)...)
		
		for _, c := range tfConds {
			conditions = append(conditions, &client.EnforcementPolicyConditionCreate{
				Type: c.Type.ValueString(), Name: c.Name.ValueString(), Oper: c.Oper.ValueString(), Value: c.Value.ValueString(),
			})
		}

		apiRules = append(apiRules, &client.EnforcementPolicyRuleCreate{
			EnforcementProfileNames: profiles,
			Condition:               conditions,
		})
	}
	return apiRules
}

func expandPolicyRulesUpdate(ctx context.Context, list types.List, diags *diag.Diagnostics) []*client.EnforcementPolicyRuleUpdate {
    // Identical logic to expandPolicyRules but returns *client.EnforcementPolicyRuleUpdate
    // (Copy the logic from above, just change the struct types)
	if list.IsNull() || list.IsUnknown() { return nil }
	var tfRules []policyRuleModel
	diags.Append(list.ElementsAs(ctx, &tfRules, false)...)
	if diags.HasError() { return nil }

	var apiRules []*client.EnforcementPolicyRuleUpdate
	for _, item := range tfRules {
		var profiles []string
		diags.Append(item.EnforcementProfileNames.ElementsAs(ctx, &profiles, false)...)
		
		var conditions []*client.EnforcementPolicyConditionUpdate
		var tfConds []policyConditionModel
		diags.Append(item.Condition.ElementsAs(ctx, &tfConds, false)...)
		
		for _, c := range tfConds {
			conditions = append(conditions, &client.EnforcementPolicyConditionUpdate{
				Type: c.Type.ValueString(), Name: c.Name.ValueString(), Oper: c.Oper.ValueString(), Value: c.Value.ValueString(),
			})
		}

		apiRules = append(apiRules, &client.EnforcementPolicyRuleUpdate{
			EnforcementProfileNames: profiles,
			Condition:               conditions,
		})
	}
	return apiRules
}

func flattenPolicyRules(ctx context.Context, apiRules []*client.EnforcementPolicyRuleResult) (types.List, diag.Diagnostics) {
	if len(apiRules) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: policyRuleModel{}.attrTypes()}), nil
	}
	var tfRules []policyRuleModel
	for _, item := range apiRules {
		profileList, diags := types.ListValueFrom(ctx, types.StringType, item.EnforcementProfileNames)
		if diags.HasError() { return types.ListNull(types.ObjectType{AttrTypes: policyRuleModel{}.attrTypes()}), diags }

		var tfConds []policyConditionModel
		for _, c := range item.Condition {
			tfConds = append(tfConds, policyConditionModel{
				Type: types.StringValue(c.Type), Name: types.StringValue(c.Name), Oper: types.StringValue(c.Oper), Value: types.StringValue(c.Value),
			})
		}
		condList, diags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: policyConditionModel{}.attrTypes()}, tfConds)
        if diags.HasError() { return types.ListNull(types.ObjectType{AttrTypes: policyRuleModel{}.attrTypes()}), diags }

		tfRules = append(tfRules, policyRuleModel{
			EnforcementProfileNames: profileList,
			Condition:               condList,
		})
	}
	return types.ListValueFrom(ctx, types.ObjectType{AttrTypes: policyRuleModel{}.attrTypes()}, tfRules)
}

func (m policyRuleModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"enforcement_profile_names": types.ListType{ElemType: types.StringType},
		"condition": types.ListType{ElemType: types.ObjectType{AttrTypes: policyConditionModel{}.attrTypes()}},
	}
}

func (m policyConditionModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type": types.StringType, "name": types.StringType, "oper": types.StringType, "value": types.StringType,
	}
}