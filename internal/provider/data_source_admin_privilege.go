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
	_ datasource.DataSource              = &adminPrivilegeDataSource{}
	_ datasource.DataSourceWithConfigure = &adminPrivilegeDataSource{}
)

// NewAdminPrivilegeDataSource is a helper function to simplify the provider implementation.
func NewAdminPrivilegeDataSource() datasource.DataSource {
	return &adminPrivilegeDataSource{}
}

// adminPrivilegeDataSource is the data source implementation.
type adminPrivilegeDataSource struct {
	client client.ClientInterface
}

// adminPrivilegeDataSourceModel maps the data source schema data.
type adminPrivilegeDataSourceModel struct {
	ID                   types.Int64  `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	Description          types.String `tfsdk:"description"`
	AccessType           types.String `tfsdk:"access_type"`
	CppmPrivileges       types.Map    `tfsdk:"cppm_privileges"`
	InsightPrivileges    types.Map    `tfsdk:"insight_privileges"`
	AllowPasswords       types.Bool   `tfsdk:"allow_passwords"`
	AllowSecurityConfigs types.Bool   `tfsdk:"allow_security_configs"`
}

// Metadata returns the data source type name.
func (d *adminPrivilegeDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_admin_privilege"
}

// Schema defines the schema for the data source.
func (d *adminPrivilegeDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves the details of a specific admin privilege in ClearPass by its numeric ID or name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				MarkdownDescription: "Numeric ID of the admin privilege. Specify either `id` or `name` to look up an admin privilege.",
				Optional:            true,
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The unique name of the admin privilege. Specify either `id` or `name` to look up an admin privilege.",
				Optional:            true,
				Computed:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Description of the admin privilege.",
				Computed:            true,
			},
			"access_type": schema.StringAttribute{
				MarkdownDescription: "Access type of the admin privilege (UI, API, FULL).",
				Computed:            true,
			},
			"cppm_privileges": schema.MapAttribute{
				MarkdownDescription: "Privilege list for ClearPass Policy Manager in JSON object format.",
				Computed:            true,
				ElementType:         types.StringType,
			},
			"insight_privileges": schema.MapAttribute{
				MarkdownDescription: "Privilege list for ClearPass Insight in JSON object format.",
				Computed:            true,
				ElementType:         types.StringType,
			},
			"allow_passwords": schema.BoolAttribute{
				MarkdownDescription: "Whether passwords may be displayed in responses.",
				Computed:            true,
			},
			"allow_security_configs": schema.BoolAttribute{
				MarkdownDescription: "Whether the user has access to security configuration.",
				Computed:            true,
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *adminPrivilegeDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *adminPrivilegeDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state adminPrivilegeDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.ID.IsNull() && state.Name.IsNull() {
		resp.Diagnostics.AddError(
			"Missing Configuration",
			"Either 'id' or 'name' must be configured to read an admin privilege.",
		)
		return
	}

	var privilege *client.AdminPrivilegeResult
	var err error

	if !state.ID.IsNull() {
		privilege, err = d.client.GetAdminPrivilege(ctx, int(state.ID.ValueInt64()))
	} else {
		privilege, err = d.client.GetAdminPrivilegeByName(ctx, state.Name.ValueString())
	}

	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Admin Privilege",
			"Could not read ClearPass admin privilege: "+err.Error(),
		)
		return
	}

	if privilege == nil {
		if !state.ID.IsNull() {
			resp.Diagnostics.AddError(
				"ClearPass Admin Privilege Not Found",
				fmt.Sprintf("Admin privilege with ID %d not found", state.ID.ValueInt64()),
			)
		} else {
			resp.Diagnostics.AddError(
				"ClearPass Admin Privilege Not Found",
				fmt.Sprintf("Admin privilege with name '%s' not found", state.Name.ValueString()),
			)
		}
		return
	}

	// Map response body to model
	state.ID = types.Int64Value(int64(privilege.ID))
	state.Name = types.StringValue(privilege.Name)
	state.Description = types.StringValue(privilege.Description)
	state.AccessType = types.StringValue(privilege.AccessType)
	state.AllowPasswords = types.BoolValue(privilege.AllowPasswords)
	state.AllowSecurityConfigs = types.BoolValue(privilege.AllowSecurityConfigs)

	if len(privilege.CppmPrivileges) > 0 {
		cppm, diag := types.MapValueFrom(ctx, types.StringType, privilege.CppmPrivileges)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.CppmPrivileges = cppm
	} else {
		state.CppmPrivileges = types.MapNull(types.StringType)
	}

	if len(privilege.InsightPrivileges) > 0 {
		insight, diag := types.MapValueFrom(ctx, types.StringType, privilege.InsightPrivileges)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.InsightPrivileges = insight
	} else {
		state.InsightPrivileges = types.MapNull(types.StringType)
	}

	// Set state
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
