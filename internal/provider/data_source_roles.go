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
	_ datasource.DataSource              = &rolesDataSource{}
	_ datasource.DataSourceWithConfigure = &rolesDataSource{}
)

// NewRolesDataSource is a helper function to simplify the provider implementation.
func NewRolesDataSource() datasource.DataSource {
	return &rolesDataSource{}
}

// rolesDataSource is the data source implementation.
type rolesDataSource struct {
	client client.ClientInterface
}

// rolesDataSourceModel maps the data source schema data.
type rolesDataSourceModel struct {
	Filter types.String      `tfsdk:"filter"`
	Roles  []rolesModelItems `tfsdk:"roles"`
}

// rolesModelItems maps the items in the roles list.
type rolesModelItems struct {
	ID          types.Int64  `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
}

// Metadata returns the data source type name.
func (d *rolesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_roles"
}

// Schema defines the schema for the data source.
func (d *rolesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Data source for a list of ClearPass roles. " +
			"Use this to query multiple roles, optionally using a JSON filter.",
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Description: "JSON filter expression specifying the items to return (e.g., `{\"name\":{\"$contains\":\"Admin\"}}`).",
				Optional:    true,
			},
			"roles": schema.ListNestedAttribute{
				Description: "List of roles matching the filter.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							Description: "Numeric ID of the role.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Name of the role.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "Description of the role.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *rolesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *rolesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state rolesDataSourceModel

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
	roles, err := d.client.GetRoles(ctx, filter, nil, nil, &limit, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Roles",
			"Could not read ClearPass roles: "+err.Error(),
		)
		return
	}

	if roles == nil || len(roles.Embedded.Items) == 0 {
		state.Roles = []rolesModelItems{}
	} else {
		for _, role := range roles.Embedded.Items {
			state.Roles = append(state.Roles, rolesModelItems{
				ID:          types.Int64Value(int64(role.ID)),
				Name:        types.StringValue(role.Name),
				Description: types.StringValue(role.Description),
			})
		}
	}

	// Set state
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
