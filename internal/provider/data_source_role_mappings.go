package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-clearpass/internal/client"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &roleMappingsDataSource{}
	_ datasource.DataSourceWithConfigure = &roleMappingsDataSource{}
)

// NewRoleMappingsDataSource is a helper function to simplify the provider implementation.
func NewRoleMappingsDataSource() datasource.DataSource {
	return &roleMappingsDataSource{}
}

// roleMappingsDataSource is the data source implementation.
type roleMappingsDataSource struct {
	client client.ClientInterface
}

// roleMappingsDataSourceModel maps the data source schema data.
type roleMappingsDataSourceModel struct {
	Filter       types.String             `tfsdk:"filter"`
	RoleMappings []roleMappingsModelItems `tfsdk:"role_mappings"`
}

// roleMappingsModelItems maps the items in the role mappings list.
type roleMappingsModelItems struct {
	ID              types.Int64                `tfsdk:"id"`
	Name            types.String               `tfsdk:"name"`
	Description     types.String               `tfsdk:"description"`
	DefaultRoleName types.String               `tfsdk:"default_role_name"`
	RuleCombineAlgo types.String               `tfsdk:"rule_combine_algo"`
	Rules           []roleMappingRulesSettings `tfsdk:"rules"`
}

// Metadata returns the data source type name.
func (d *roleMappingsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role_mappings"
}

// Schema defines the schema for the data source.
func (d *roleMappingsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of ClearPass Role Mapping policies, optionally filtered using a JSON filter expression. " +
			"Role Mapping policies assign roles to users based on attribute conditions evaluated during authentication.",
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				MarkdownDescription: "JSON filter expression to narrow results (e.g., `{\"name\":{\"$contains\":\"Guest\"}}`).",
				Optional:            true,
			},
			"role_mappings": schema.ListNestedAttribute{
				MarkdownDescription: "List of role mapping policies matching the filter.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							MarkdownDescription: "Numeric ID of the role mapping.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "The unique name of the role mapping policy.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "A human-readable description of the role mapping policy.",
							Computed:            true,
						},
						"default_role_name": schema.StringAttribute{
							MarkdownDescription: "The default role assigned when no rules match.",
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
										MarkdownDescription: "The set of conditions evaluated for this rule.",
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
				},
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *roleMappingsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// Read refreshes the Terraform state with the latest data.
func (d *roleMappingsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state roleMappingsDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var filter *string
	if !state.Filter.IsNull() {
		f := state.Filter.ValueString()
		filter = &f
	}

	limit := 1000 // Max limit per API spec
	roleMaps, err := d.client.GetRoleMappings(ctx, filter, nil, nil, &limit, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Role Mappings",
			"Could not read ClearPass role mappings: "+err.Error(),
		)
		return
	}

	if roleMaps == nil || len(roleMaps.Embedded.Items) == 0 {
		state.RoleMappings = []roleMappingsModelItems{}
	} else {
		for _, roleMap := range roleMaps.Embedded.Items {
			item := roleMappingsModelItems{
				ID:              types.Int64Value(int64(roleMap.ID)),
				Name:            types.StringValue(roleMap.Name),
				Description:     types.StringValue(roleMap.Description),
				DefaultRoleName: types.StringValue(roleMap.DefaultRoleName),
				RuleCombineAlgo: types.StringValue(roleMap.RuleCombineAlgo),
				Rules:           []roleMappingRulesSettings{},
			}

			if len(roleMap.Rules) > 0 {
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
					item.Rules = append(item.Rules, tfRule)
				}
			}
			state.RoleMappings = append(state.RoleMappings, item)
		}
	}

	// Set state
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
