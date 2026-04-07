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
	_ datasource.DataSource              = &networkDeviceGroupDataSource{}
	_ datasource.DataSourceWithConfigure = &networkDeviceGroupDataSource{}
)

// NewNetworkDeviceGroupDataSource is a helper function to simplify the provider implementation.
func NewNetworkDeviceGroupDataSource() datasource.DataSource {
	return &networkDeviceGroupDataSource{}
}

// networkDeviceGroupDataSource is the data source implementation.
type networkDeviceGroupDataSource struct {
	client client.ClientInterface
}

// networkDeviceGroupDataSourceModel maps the data source schema data.
type networkDeviceGroupDataSourceModel struct {
	ID          types.Int64  `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	GroupFormat types.String `tfsdk:"group_format"`
	Value       types.String `tfsdk:"value"`
}

// Metadata returns the data source type name.
func (d *networkDeviceGroupDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_device_group"
}

// Schema defines the schema for the data source.
func (d *networkDeviceGroupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves the details of a specific network device group in ClearPass by its numeric ID or name. " +
			"Network device groups organize network devices by subnet, regex pattern, or explicit list.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				MarkdownDescription: "Numeric ID of the network device group. Specify either `id` or `name` to look up a group.",
				Optional:            true,
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Unique name of the network device group. Specify either `id` or `name` to look up a group.",
				Optional:            true,
				Computed:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Description of the network device group.",
				Computed:            true,
			},
			"group_format": schema.StringAttribute{
				MarkdownDescription: "Format of the network devices in this group (`subnet`, `regex`, or `list`).",
				Computed:            true,
			},
			"value": schema.StringAttribute{
				MarkdownDescription: "Network devices in the specified format.",
				Computed:            true,
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *networkDeviceGroupDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *networkDeviceGroupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state networkDeviceGroupDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.ID.IsNull() && state.Name.IsNull() {
		resp.Diagnostics.AddError(
			"Missing Configuration",
			"Either 'id' or 'name' must be configured to read a network device group.",
		)
		return
	}

	var group *client.NetworkDeviceGroupResult
	var err error

	if !state.ID.IsNull() {
		group, err = d.client.GetNetworkDeviceGroup(ctx, int(state.ID.ValueInt64()))
	} else {
		group, err = d.client.GetNetworkDeviceGroupByName(ctx, state.Name.ValueString())
	}

	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Network Device Group",
			"Could not read ClearPass network device group: "+err.Error(),
		)
		return
	}

	if group == nil {
		if !state.ID.IsNull() {
			resp.Diagnostics.AddError(
				"ClearPass Network Device Group Not Found",
				fmt.Sprintf("Network device group with ID %d not found", state.ID.ValueInt64()),
			)
		} else {
			resp.Diagnostics.AddError(
				"ClearPass Network Device Group Not Found",
				fmt.Sprintf("Network device group with name '%s' not found", state.Name.ValueString()),
			)
		}
		return
	}

	// Map response body to model
	state.ID = types.Int64Value(int64(group.ID))
	state.Name = types.StringValue(group.Name)
	state.Description = types.StringValue(group.Description)
	state.GroupFormat = types.StringValue(group.GroupFormat)
	state.Value = types.StringValue(group.Value)

	// Set state
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
