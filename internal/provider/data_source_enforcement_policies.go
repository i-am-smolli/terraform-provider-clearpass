package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-clearpass/internal/client"
)

var (
	_ datasource.DataSource              = &enforcementPoliciesDataSource{}
	_ datasource.DataSourceWithConfigure = &enforcementPoliciesDataSource{}
)

func NewEnforcementPoliciesDataSource() datasource.DataSource {
	return &enforcementPoliciesDataSource{}
}

type enforcementPoliciesDataSource struct {
	client client.ClientInterface
}

func (d *enforcementPoliciesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_enforcement_policies"
}

func (d *enforcementPoliciesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Data source for retrieving a list of Enforcement Policies from ClearPass.",
		Attributes: map[string]schema.Attribute{
			"policies": schema.ListNestedAttribute{
				Description: "List of Enforcement Policies.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							Description: "The numeric ID of the Enforcement Policy in ClearPass.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The unique name of the Enforcement Policy.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "A human-readable description of the Enforcement Policy.",
							Computed:    true,
						},
						"enforcement_type": schema.StringAttribute{
							Description: "The type of the Enforcement Policy indicating its application context (e.g., RADIUS, TACACS, WEBAUTH, Application, Event).",
							Computed:    true,
						},
						"default_enforcement_profile": schema.StringAttribute{
							Description: "The profile applied as a fallback if none of the policy rules match the session conditions.",
							Computed:    true,
						},
						"rule_eval_algo": schema.StringAttribute{
							Description: "The logic used to evaluate the rules. Typically 'first-applicable' (stops after the first match) or 'evaluate-all' (processes all rules).",
							Computed:    true,
						},
						"rules": schema.ListNestedAttribute{
							Description: "The ordered list of conditional rules configured for the Enforcement Policy.",
							Computed:    true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"enforcement_profile_names": schema.ListAttribute{
										Description: "List of Enforcement Profile names that are applied when this rule's conditions are met.",
										ElementType: types.StringType,
										Computed:    true,
									},
									"condition": schema.ListNestedAttribute{
										Description: "The set of conditions that must be evaluated for this rule.",
										Computed:    true,
										NestedObject: schema.NestedAttributeObject{
											Attributes: map[string]schema.Attribute{
												"type": schema.StringAttribute{
													Description: "The namespace or category of the condition (e.g., 'Radius:IETF', 'Tips', 'Connection').",
													Computed:    true,
												},
												"name": schema.StringAttribute{
													Description: "The specific attribute name within the condition type (e.g., 'Calling-Station-Id', 'Role').",
													Computed:    true,
												},
												"oper": schema.StringAttribute{
													Description: "The operator used for comparison (e.g., 'EQUALS', 'CONTAINS', 'BELONGS_TO', 'MATCHES_REGEX').",
													Computed:    true,
												},
												"value": schema.StringAttribute{
													Description: "The value against which the attribute is compared.",
													Computed:    true,
												},
											},
										},
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

func (d *enforcementPoliciesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = req.ProviderData.(client.ClientInterface)
}

func (d *enforcementPoliciesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state struct {
		Policies []struct {
			ID                        types.Int64  `tfsdk:"id"`
			Name                      types.String `tfsdk:"name"`
			Description               types.String `tfsdk:"description"`
			EnforcementType           types.String `tfsdk:"enforcement_type"`
			DefaultEnforcementProfile types.String `tfsdk:"default_enforcement_profile"`
			RuleEvalAlgo              types.String `tfsdk:"rule_eval_algo"`
			Rules                     types.List   `tfsdk:"rules"`
		} `tfsdk:"policies"`
	}

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result, err := d.client.GetEnforcementPolicies(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Enforcement Policies",
			"Could not read Enforcement Policies: "+err.Error(),
		)
		return
	}

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

	for _, policy := range result.Embedded.Items {

		var rulesList types.List

		if len(policy.Rules) > 0 {
			var mappedRules []struct {
				ProfileNames types.List `tfsdk:"enforcement_profile_names"`
				Condition    types.List `tfsdk:"condition"`
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
						objMap := map[string]attr.Type{
							"type":  types.StringType,
							"name":  types.StringType,
							"oper":  types.StringType,
							"value": types.StringType,
						}
						attrMap := map[string]types.String{
							"type":  c["type"],
							"name":  c["name"],
							"oper":  c["oper"],
							"value": c["value"],
						}
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
				rList, diags := types.ListValueFrom(ctx, ruleElementType, ruleObjs)
				resp.Diagnostics.Append(diags...)
				rulesList = rList
			} else {
				rulesList, _ = types.ListValueFrom(ctx, ruleElementType, []types.Object{})
			}
		} else {
			rulesList, _ = types.ListValueFrom(ctx, ruleElementType, []types.Object{})
		}

		state.Policies = append(state.Policies, struct {
			ID                        types.Int64  `tfsdk:"id"`
			Name                      types.String `tfsdk:"name"`
			Description               types.String `tfsdk:"description"`
			EnforcementType           types.String `tfsdk:"enforcement_type"`
			DefaultEnforcementProfile types.String `tfsdk:"default_enforcement_profile"`
			RuleEvalAlgo              types.String `tfsdk:"rule_eval_algo"`
			Rules                     types.List   `tfsdk:"rules"`
		}{
			ID:                        types.Int64Value(int64(policy.ID)),
			Name:                      types.StringValue(policy.Name),
			Description:               types.StringValue(policy.Description),
			EnforcementType:           types.StringValue(policy.EnforcementType),
			DefaultEnforcementProfile: types.StringValue(policy.DefaultEnforcementProfile),
			RuleEvalAlgo:              types.StringValue(policy.RuleEvalAlgo),
			Rules:                     rulesList,
		})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
