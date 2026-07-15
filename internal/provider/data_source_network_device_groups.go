package provider

import (
	"context"
	"fmt"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &networkDeviceGroupsDataSource{}
	_ datasource.DataSourceWithConfigure = &networkDeviceGroupsDataSource{}
)

func NewNetworkDeviceGroupsDataSource() datasource.DataSource {
	return &networkDeviceGroupsDataSource{}
}

type networkDeviceGroupsDataSource struct {
	client client.ClientInterface
}

type networkDeviceGroupsModel struct {
	Filter              types.String                   `tfsdk:"filter"`
	Sort                types.String                   `tfsdk:"sort"`
	Offset              types.Int64                    `tfsdk:"offset"`
	Limit               types.Int64                    `tfsdk:"limit"`
	CalculateCount      types.Bool                     `tfsdk:"calculate_count"`
	NetworkDeviceGroups []networkDeviceGroupModelItems `tfsdk:"network_device_groups"`
}

type networkDeviceGroupModelItems struct {
	ID          types.Int64  `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	GroupFormat types.String `tfsdk:"group_format"`
	Value       types.String `tfsdk:"value"`
}

func (d *networkDeviceGroupsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_device_groups"
}

func (d *networkDeviceGroupsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of ClearPass network device groups, optionally filtered.",
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				MarkdownDescription: "JSON filter expression specifying the items to return.",
				Optional:            true,
			},
			"sort": schema.StringAttribute{
				MarkdownDescription: "Sort ordering for returned items.",
				Optional:            true,
			},
			"offset": schema.Int64Attribute{
				MarkdownDescription: "Zero based offset to start from.",
				Optional:            true,
			},
			"limit": schema.Int64Attribute{
				MarkdownDescription: "Maximum number of items to return.",
				Optional:            true,
			},
			"calculate_count": schema.BoolAttribute{
				MarkdownDescription: "Whether to calculate the total item count.",
				Optional:            true,
			},
			"network_device_groups": schema.ListNestedAttribute{
				MarkdownDescription: "List of network device groups matching the query.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							MarkdownDescription: "Numeric ID of the network device group.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "Name of the network device group.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "Description of the network device group.",
							Computed:            true,
						},
						"group_format": schema.StringAttribute{
							MarkdownDescription: "Format of the network devices in this group.",
							Computed:            true,
						},
						"value": schema.StringAttribute{
							MarkdownDescription: "Network devices in the specified format.",
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

func (d *networkDeviceGroupsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected client.ClientInterface, got: %T", req.ProviderData),
		)
		return
	}
	d.client = c
}

func (d *networkDeviceGroupsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state networkDeviceGroupsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var filter *string
	if !state.Filter.IsNull() {
		f := state.Filter.ValueString()
		filter = &f
	}
	var sort *string
	if !state.Sort.IsNull() {
		s := state.Sort.ValueString()
		sort = &s
	}
	var offset *int
	if !state.Offset.IsNull() {
		o := int(state.Offset.ValueInt64())
		offset = &o
	}
	var limit *int
	if !state.Limit.IsNull() {
		l := int(state.Limit.ValueInt64())
		limit = &l
	} else {
		// ponytail: default limit to 1000 to fetch all by default
		defaultLimit := 1000
		limit = &defaultLimit
	}
	var calculateCount *bool
	if !state.CalculateCount.IsNull() {
		c := state.CalculateCount.ValueBool()
		calculateCount = &c
	}

	groups, err := d.client.GetNetworkDeviceGroups(ctx, filter, sort, offset, limit, calculateCount)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Network Device Groups",
			"Could not read network device groups: "+err.Error(),
		)
		return
	}

	state.NetworkDeviceGroups = make([]networkDeviceGroupModelItems, 0)
	if groups != nil && len(groups.Embedded.Items) > 0 {
		for _, group := range groups.Embedded.Items {
			state.NetworkDeviceGroups = append(state.NetworkDeviceGroups, networkDeviceGroupModelItems{
				ID:          types.Int64Value(int64(group.ID)),
				Name:        types.StringValue(group.Name),
				Description: types.StringValue(group.Description),
				GroupFormat: types.StringValue(group.GroupFormat),
				Value:       types.StringValue(group.Value),
			})
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
