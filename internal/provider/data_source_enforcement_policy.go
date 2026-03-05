package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-clearpass/internal/client"
)

var (
	_ datasource.DataSource              = &enforcementPolicyDataSource{}
	_ datasource.DataSourceWithConfigure = &enforcementPolicyDataSource{}
)

func NewEnforcementPolicyDataSource() datasource.DataSource {
	return &enforcementPolicyDataSource{}
}

type enforcementPolicyDataSource struct {
	client client.ClientInterface
}

func (d *enforcementPolicyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_enforcement_policy"
}

func (d *enforcementPolicyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Data source for retrieving a single Enforcement Policy from ClearPass. " +
			"Enforcement Policies evaluate conditions to determine which Enforcement Profiles " +
			"should be applied to a session.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				MarkdownDescription: "The numeric ID of the Enforcement Policy in ClearPass.",
				Required:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The unique name of the Enforcement Policy.",
				Computed:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A human-readable description of the Enforcement Policy.",
				Computed:            true,
			},
			"enforcement_type": schema.StringAttribute{
				MarkdownDescription: "The type of the Enforcement Policy indicating its application context (e.g., RADIUS, TACACS, WEBAUTH, Application, Event).",
				Computed:            true,
			},
			"default_enforcement_profile": schema.StringAttribute{
				MarkdownDescription: "The profile applied as a fallback if none of the policy rules match the session conditions.",
				Computed:            true,
			},
			"rule_eval_algo": schema.StringAttribute{
				MarkdownDescription: "The logic used to evaluate the rules. Typically 'first-applicable' (stops after the first match) or 'evaluate-all' (processes all rules).",
				Computed:            true,
			},
			"rules": schema.ListNestedAttribute{
				MarkdownDescription: "The ordered list of conditional rules configured for the Enforcement Policy.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"enforcement_profile_names": schema.ListAttribute{
							MarkdownDescription: "List of Enforcement Profile names that are applied when this rule's conditions are met.",
							ElementType:         types.StringType,
							Computed:            true,
						},
						"condition": schema.ListNestedAttribute{
							MarkdownDescription: "The set of conditions that must be evaluated for this rule.",
							Computed:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										MarkdownDescription: "The namespace or category of the condition (e.g., 'Radius:IETF', 'Tips', 'Connection').",
										Computed:            true,
									},
									"name": schema.StringAttribute{
										MarkdownDescription: "The specific attribute name within the condition type (e.g., 'Calling-Station-Id', 'Role').",
										Computed:            true,
									},
									"oper": schema.StringAttribute{
										MarkdownDescription: "The operator used for comparison (e.g., 'EQUALS', 'CONTAINS', 'BELONGS_TO', 'MATCHES_REGEX').",
										Computed:            true,
									},
									"value": schema.StringAttribute{
										MarkdownDescription: "The value against which the attribute is compared.",
										Computed:            true,
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

func (d *enforcementPolicyDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = req.ProviderData.(client.ClientInterface)
}

func (d *enforcementPolicyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state struct {
		ID                        types.Int64  `tfsdk:"id"`
		Name                      types.String `tfsdk:"name"`
		Description               types.String `tfsdk:"description"`
		EnforcementType           types.String `tfsdk:"enforcement_type"`
		DefaultEnforcementProfile types.String `tfsdk:"default_enforcement_profile"`
		RuleEvalAlgo              types.String `tfsdk:"rule_eval_algo"`
		Rules                     types.List   `tfsdk:"rules"`
	}

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read Timeout setup
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	policy, err := d.client.GetEnforcementPolicy(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Enforcement Policy",
			fmt.Sprintf("Could not read Enforcement Policy ID %d: %s", state.ID.ValueInt64(), err.Error()),
		)
		return
	}

	if policy == nil {
		resp.Diagnostics.AddError(
			"Enforcement Policy Not Found",
			fmt.Sprintf("Enforcement Policy ID %d was not found in ClearPass.", state.ID.ValueInt64()),
		)
		return
	}

	state.ID = types.Int64Value(int64(policy.ID))
	state.Name = types.StringValue(policy.Name)
	state.Description = types.StringValue(policy.Description)
	state.EnforcementType = types.StringValue(policy.EnforcementType)
	state.DefaultEnforcementProfile = types.StringValue(policy.DefaultEnforcementProfile)
	state.RuleEvalAlgo = types.StringValue(policy.RuleEvalAlgo)

	// Map rules
	if len(policy.Rules) > 0 {
		var mappedRules []struct {
			ProfileNames types.List `tfsdk:"enforcement_profile_names"`
			Condition    types.List `tfsdk:"condition"`
		}

		// Types declarations needed for ListValueFrom
		conditionElementType := types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"type":  types.StringType,
				"name":  types.StringType,
				"oper":  types.StringType,
				"value": types.StringType,
			},
		}

		for _, r := range policy.Rules {
			var mappedProfiles []types.String
			for _, pn := range r.EnforcementProfileNames {
				mappedProfiles = append(mappedProfiles, types.StringValue(pn))
			}
			profilesList, diags := types.ListValueFrom(ctx, types.StringType, mappedProfiles)
			resp.Diagnostics.Append(diags...)

			var mappedConditions []map[string]types.String
			for _, cond := range r.Condition {
				mappedConditions = append(mappedConditions, map[string]types.String{
					"type":  types.StringValue(cond.Type),
					"name":  types.StringValue(cond.Name),
					"oper":  types.StringValue(cond.Oper),
					"value": types.StringValue(cond.Value),
				})
			}

			var conditionList types.List
			if len(mappedConditions) > 0 {
				var conditionObjs []types.Object
				for _, c := range mappedConditions {
					// We construct the Object type map
					objMap := map[string]attr.Type{
						"type":  types.StringType,
						"name":  types.StringType,
						"oper":  types.StringType,
						"value": types.StringType,
					}
					// and construct a set of AttrValues
					attrMap := map[string]types.String{
						"type":  c["type"],
						"name":  c["name"],
						"oper":  c["oper"],
						"value": c["value"],
					}
					// Convert map[string]types.String into map[string]attr.Value
					valMap := make(map[string]attr.Value)
					for k, v := range attrMap {
						valMap[k] = v
					}

					obj, diags := types.ObjectValue(objMap, valMap)
					resp.Diagnostics.Append(diags...)
					conditionObjs = append(conditionObjs, obj)
				}

				condList, diags := types.ListValueFrom(ctx, conditionElementType, conditionObjs)
				resp.Diagnostics.Append(diags...)
				conditionList = condList
			} else {
				// empty list
				condList, diags := types.ListValueFrom(ctx, conditionElementType, []types.Object{})
				resp.Diagnostics.Append(diags...)
				conditionList = condList
			}

			mappedRules = append(mappedRules, struct {
				ProfileNames types.List `tfsdk:"enforcement_profile_names"`
				Condition    types.List `tfsdk:"condition"`
			}{
				ProfileNames: profilesList,
				Condition:    conditionList,
			})
		}

		// define rule type
		ruleElementType := types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"enforcement_profile_names": types.ListType{ElemType: types.StringType},
				"condition":                 types.ListType{ElemType: conditionElementType},
			},
		}

		if len(mappedRules) > 0 {
			var ruleObjs []types.Object
			for _, mr := range mappedRules {
				objMap := map[string]attr.Type{
					"enforcement_profile_names": types.ListType{ElemType: types.StringType},
					"condition":                 types.ListType{ElemType: conditionElementType},
				}
				valMap := map[string]attr.Value{
					"enforcement_profile_names": mr.ProfileNames,
					"condition":                 mr.Condition,
				}
				obj, diags := types.ObjectValue(objMap, valMap)
				resp.Diagnostics.Append(diags...)
				ruleObjs = append(ruleObjs, obj)
			}
			rulesList, diags := types.ListValueFrom(ctx, ruleElementType, ruleObjs)
			resp.Diagnostics.Append(diags...)
			state.Rules = rulesList
		} else {
			state.Rules, _ = types.ListValueFrom(ctx, ruleElementType, []types.Object{})
		}
	} else {
		// Define the type properly even for empty
		conditionElementType := types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"type":  types.StringType,
				"name":  types.StringType,
				"oper":  types.StringType,
				"value": types.StringType,
			},
		}
		ruleElementType := types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"enforcement_profile_names": types.ListType{ElemType: types.StringType},
				"condition":                 types.ListType{ElemType: conditionElementType},
			},
		}
		state.Rules, _ = types.ListValueFrom(ctx, ruleElementType, []types.Object{})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
