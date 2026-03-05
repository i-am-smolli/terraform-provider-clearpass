package provider

import (
	"context"
	"fmt"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &EnforcementProfilesDataSource{}

func NewEnforcementProfilesDataSource() datasource.DataSource {
	return &EnforcementProfilesDataSource{}
}

type EnforcementProfilesDataSource struct {
	client client.ClientInterface
}

type EnforcementProfilesDataSourceModel struct {
	ID    types.String                                 `tfsdk:"id"`
	Items []EnforcementProfilesListItemDataSourceModel `tfsdk:"items"`
}

type EnforcementProfilesListItemDataSourceModel struct {
	ID          types.Int64  `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Type        types.String `tfsdk:"type"`
}

func (d *EnforcementProfilesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_enforcement_profiles"
}

func (d *EnforcementProfilesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a comprehensive list of all Enforcement Profiles available in ClearPass. " +
			"This can be useful for discovering available profiles or referencing multiple profiles in other configurations.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Placeholder identifier to satisfy Terraform framework requirements.",
				Computed:            true,
			},
		},
		Blocks: map[string]schema.Block{
			"items": schema.ListNestedBlock{
				MarkdownDescription: "A list containing the enforcement profiles and their basic summary information.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							MarkdownDescription: "Numeric ID of the Enforcement Profile.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "Name of the Enforcement Profile.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "Human-readable description of the Enforcement Profile.",
							Computed:            true,
						},
						"type": schema.StringAttribute{
							MarkdownDescription: "The type of enforcement profile (e.g., 'RADIUS', 'TACACS', 'Agent', 'Aruba_DUR').",
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

func (d *EnforcementProfilesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected client.ClientInterface, got: %T.", req.ProviderData))
		return
	}

	d.client = client
}

func (d *EnforcementProfilesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data EnforcementProfilesDataSourceModel

	result, err := d.client.GetEnforcementProfiles(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read enforcement profiles: %s", err))
		return
	}

	data.ID = types.StringValue("placeholder")

	for _, item := range result.Embedded.Items {
		data.Items = append(data.Items, EnforcementProfilesListItemDataSourceModel{
			ID:          types.Int64Value(int64(item.ID)),
			Name:        types.StringValue(item.Name),
			Description: types.StringValue(item.Description),
			Type:        types.StringValue(item.Type),
		})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
