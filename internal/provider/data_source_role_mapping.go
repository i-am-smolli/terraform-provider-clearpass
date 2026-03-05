package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-clearpass/internal/client"
)

var (
	_ datasource.DataSource              = &roleMappingDataSource{}
	_ datasource.DataSourceWithConfigure = &roleMappingDataSource{}
)

func NewRoleMappingDataSource() datasource.DataSource {
	return &roleMappingDataSource{}
}

type roleMappingDataSource struct {
	client client.ClientInterface
}

type roleMappingDataSourceModel struct {
	ID              types.Int64                `tfsdk:"id"`
	Name            types.String               `tfsdk:"name"`
	Description     types.String               `tfsdk:"description"`
	DefaultRoleName types.String               `tfsdk:"default_role_name"`
	RuleCombineAlgo types.String               `tfsdk:"rule_combine_algo"`
	Rules           []roleMappingRulesSettings `tfsdk:"rules"`
}

type roleMappingRulesSettings struct {
	MatchType types.String                   `tfsdk:"match_type"`
	RoleName  types.String                   `tfsdk:"role_name"`
	Condition []roleMappingConditionSettings `tfsdk:"condition"`
}

type roleMappingConditionSettings struct {
	Type          types.String `tfsdk:"type"`
	Name          types.String `tfsdk:"name"`
	Oper          types.String `tfsdk:"oper"`
	Value         types.String `tfsdk:"value"`
	ValueDispName types.String `tfsdk:"value_disp_name"`
}

func (d *roleMappingDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role_mapping"
}

func (d *roleMappingDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves the details of a specific Role Mapping policy in ClearPass by its ID or name. " +
			"Role Mapping policies assign roles to users based on attribute conditions evaluated during authentication.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				MarkdownDescription: "Numeric ID of the role mapping. Specify either `id` or `name` to look up a role mapping.",
				Optional:            true,
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The unique name of the role mapping policy. Specify either `id` or `name` to look up a role mapping.",
				Optional:            true,
				Computed:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A human-readable description of the role mapping policy.",
				Computed:            true,
			},
			"default_role_name": schema.StringAttribute{
				MarkdownDescription: "The default role assigned when no rules match the session conditions.",
				Computed:            true,
			},
			"rule_combine_algo": schema.StringAttribute{
				MarkdownDescription: "The algorithm used to combine rule results (e.g., `first-applicable`, `evaluate-all`).",
				Computed:            true,
			},
			"rules": schema.ListNestedAttribute{
				MarkdownDescription: "Ordered list of rules evaluated to assign roles.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"match_type": schema.StringAttribute{
							MarkdownDescription: "Whether the rule matches `ANY` or `ALL` of its conditions.",
							Computed:            true,
						},
						"role_name": schema.StringAttribute{
							MarkdownDescription: "The role assigned when this rule's conditions are met.",
							Computed:            true,
						},
						"condition": schema.ListNestedAttribute{
							MarkdownDescription: "The set of conditions that must be evaluated for this rule.",
							Computed:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										MarkdownDescription: "The namespace or category of the condition (e.g., `Radius:IETF`, `Tips`, `Connection`).",
										Computed:            true,
									},
									"name": schema.StringAttribute{
										MarkdownDescription: "The specific attribute name within the condition type (e.g., `Calling-Station-Id`, `Role`).",
										Computed:            true,
									},
									"oper": schema.StringAttribute{
										MarkdownDescription: "The operator used for comparison (e.g., `EQUALS`, `CONTAINS`, `BELONGS_TO`).",
										Computed:            true,
									},
									"value": schema.StringAttribute{
										MarkdownDescription: "The value against which the attribute is compared.",
										Computed:            true,
									},
									"value_disp_name": schema.StringAttribute{
										MarkdownDescription: "Human-readable display name of the condition value.",
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

func (d *roleMappingDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected client.ClientInterface, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

func (d *roleMappingDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state roleMappingDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.ID.IsNull() && state.Name.IsNull() {
		resp.Diagnostics.AddError(
			"Missing Configuration",
			"Either 'id' or 'name' must be configured to read a role mapping.",
		)
		return
	}

	var roleMap *client.RoleMappingResult
	var err error

	if !state.ID.IsNull() {
		roleMap, err = d.client.GetRoleMapping(ctx, int(state.ID.ValueInt64()))
	} else {
		roleMap, err = d.client.GetRoleMappingByName(ctx, state.Name.ValueString())
	}

	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Role Mapping",
			"Could not read ClearPass role mapping: "+err.Error(),
		)
		return
	}

	if roleMap == nil {
		if !state.ID.IsNull() {
			resp.Diagnostics.AddError(
				"ClearPass Role Mapping Not Found",
				fmt.Sprintf("Role mapping with ID %d not found", state.ID.ValueInt64()),
			)
		} else {
			resp.Diagnostics.AddError(
				"ClearPass Role Mapping Not Found",
				fmt.Sprintf("Role mapping with name '%s' not found", state.Name.ValueString()),
			)
		}
		return
	}

	state.ID = types.Int64Value(int64(roleMap.ID))
	state.Name = types.StringValue(roleMap.Name)
	state.Description = types.StringValue(roleMap.Description)
	state.DefaultRoleName = types.StringValue(roleMap.DefaultRoleName)
	state.RuleCombineAlgo = types.StringValue(roleMap.RuleCombineAlgo)

	if len(roleMap.Rules) > 0 {
		state.Rules = make([]roleMappingRulesSettings, 0, len(roleMap.Rules))
		for _, r := range roleMap.Rules {
			tfRule := roleMappingRulesSettings{
				MatchType: types.StringValue(r.MatchType),
				RoleName:  types.StringValue(r.RoleName),
				Condition: []roleMappingConditionSettings{},
			}
			if len(r.Condition) > 0 {
				for _, c := range r.Condition {
					tfCond := roleMappingConditionSettings{
						Type:          types.StringValue(c.Type),
						Name:          types.StringValue(c.Name),
						Oper:          types.StringValue(c.Oper),
						Value:         types.StringValue(c.Value),
						ValueDispName: types.StringValue(c.ValueDispName),
					}
					tfRule.Condition = append(tfRule.Condition, tfCond)
				}
			}
			state.Rules = append(state.Rules, tfRule)
		}
	} else {
		state.Rules = []roleMappingRulesSettings{}
	}

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
