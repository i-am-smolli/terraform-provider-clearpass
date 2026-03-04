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
	_ datasource.DataSource              = &roleDataSource{}
	_ datasource.DataSourceWithConfigure = &roleDataSource{}
)

// NewRoleDataSource is a helper function to simplify the provider implementation.
func NewRoleDataSource() datasource.DataSource {
	return &roleDataSource{}
}

// roleDataSource is the data source implementation.
type roleDataSource struct {
	client client.ClientInterface
}

// roleDataSourceModel maps the data source schema data.
type roleDataSourceModel struct {
	ID          types.Int64  `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
}

// Metadata returns the data source type name.
func (d *roleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

// Schema defines the schema for the data source.
func (d *roleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a user role in ClearPass. Roles are used to define access levels " +
			"and permissions for authenticated users. Common roles include [Employee], " +
			"Guest, and custom roles for specific access requirements.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Numeric ID of the role.",
				Optional:    true,
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The unique name of the role (e.g., 'Guest', '[Employee]', '[Contractor]'). " +
					"Note: System roles typically use square brackets.",
				Optional: true,
				Computed: true,
			},
			"description": schema.StringAttribute{
				Description: "Human-readable description of the role's purpose and intended use.",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *roleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *roleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state roleDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.ID.IsNull() && state.Name.IsNull() {
		resp.Diagnostics.AddError(
			"Missing Configuration",
			"Either 'id' or 'name' must be configured to read a role.",
		)
		return
	}

	var role *client.RoleResult
	var err error

	if !state.ID.IsNull() {
		role, err = d.client.GetRole(ctx, int(state.ID.ValueInt64()))
	} else {
		role, err = d.client.GetRoleByName(ctx, state.Name.ValueString())
	}

	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Role",
			"Could not read ClearPass role ID "+state.ID.String()+": "+err.Error(),
		)
		return
	}

	if role == nil {
		if !state.ID.IsNull() {
			resp.Diagnostics.AddError(
				"ClearPass Role Not Found",
				fmt.Sprintf("Role with ID %d not found", state.ID.ValueInt64()),
			)
		} else {
			resp.Diagnostics.AddError(
				"ClearPass Role Not Found",
				fmt.Sprintf("Role with name '%s' not found", state.Name.ValueString()),
			)
		}
		return
	}

	// Map response body to model
	state.ID = types.Int64Value(int64(role.ID))
	state.Name = types.StringValue(role.Name)
	state.Description = types.StringValue(role.Description)

	// Set state
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
