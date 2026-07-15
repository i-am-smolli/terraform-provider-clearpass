package provider

import (
	"context"
	"fmt"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &networkDevicesDataSource{}
	_ datasource.DataSourceWithConfigure = &networkDevicesDataSource{}
)

func NewNetworkDevicesDataSource() datasource.DataSource {
	return &networkDevicesDataSource{}
}

type networkDevicesDataSource struct {
	client client.ClientInterface
}

type networkDevicesModel struct {
	Filter         types.String              `tfsdk:"filter"`
	Sort           types.String              `tfsdk:"sort"`
	Offset         types.Int64               `tfsdk:"offset"`
	Limit          types.Int64               `tfsdk:"limit"`
	CalculateCount types.Bool                `tfsdk:"calculate_count"`
	NetworkDevices []networkDeviceModelItems `tfsdk:"network_devices"`
}

type networkDeviceModelItems struct {
	ID                   types.Int64  `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	Description          types.String `tfsdk:"description"`
	IPAddress            types.String `tfsdk:"ip_address"`
	VendorName           types.String `tfsdk:"vendor_name"`
	VendorID             types.Int64  `tfsdk:"vendor_id"`
	CoACapable           types.Bool   `tfsdk:"coa_capable"`
	CoAPort              types.Int64  `tfsdk:"coa_port"`
	RadSecEnabled        types.Bool   `tfsdk:"radsec_enabled"`
	NADGroups            types.List   `tfsdk:"nad_groups"`
	Attributes           types.Map    `tfsdk:"attributes"`
	SNMPRead             types.Object `tfsdk:"snmp_read"`
	SNMPWrite            types.Object `tfsdk:"snmp_write"`
	RadSecConfig         types.Object `tfsdk:"radsec_config"`
	CLIConfig            types.Object `tfsdk:"cli_config"`
	OnConnectEnforcement types.Object `tfsdk:"onconnect_enforcement"`
}

func (d *networkDevicesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_devices"
}

func (d *networkDevicesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of ClearPass network devices, optionally filtered.",
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
			"network_devices": schema.ListNestedAttribute{
				MarkdownDescription: "List of network devices matching the query.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							MarkdownDescription: "Numeric ID of the network device.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "Name of the network device.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "Description of the network device.",
							Computed:            true,
						},
						"ip_address": schema.StringAttribute{
							MarkdownDescription: "IP or Subnet Address of the network device.",
							Computed:            true,
						},
						"vendor_name": schema.StringAttribute{
							MarkdownDescription: "Vendor Name of the network device.",
							Computed:            true,
						},
						"vendor_id": schema.Int64Attribute{
							MarkdownDescription: "Vendor ID of the network device.",
							Computed:            true,
						},
						"coa_capable": schema.BoolAttribute{
							MarkdownDescription: "Flag indicating CoA capability.",
							Computed:            true,
						},
						"coa_port": schema.Int64Attribute{
							MarkdownDescription: "CoA port number.",
							Computed:            true,
						},
						"radsec_enabled": schema.BoolAttribute{
							MarkdownDescription: "Flag indicating RadSec capability.",
							Computed:            true,
						},
						"nad_groups": schema.ListAttribute{
							MarkdownDescription: "List of NAD group names this device belongs to.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"attributes": schema.MapAttribute{
							MarkdownDescription: "Additional attributes.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"snmp_read": schema.SingleNestedAttribute{
							MarkdownDescription: "SNMP read settings.",
							Computed:            true,
							Attributes: map[string]schema.Attribute{
								"force_read": schema.BoolAttribute{
									MarkdownDescription: "This field is deprecated.",
									Computed:            true,
								},
								"read_arp_info": schema.BoolAttribute{
									MarkdownDescription: "Enable to read ARP table from this device.",
									Computed:            true,
								},
								"zone_name": schema.StringAttribute{
									MarkdownDescription: "Policy Manager Zone name associated with the network device.",
									Computed:            true,
								},
								"snmp_version": schema.StringAttribute{
									MarkdownDescription: "SNMP version of the network device.",
									Computed:            true,
								},
								"community_string": schema.StringAttribute{
									MarkdownDescription: "Community string of the network device. Not returned by the API.",
									Computed:            true,
								},
								"security_level": schema.StringAttribute{
									MarkdownDescription: "Security level of the network device.",
									Computed:            true,
								},
								"user": schema.StringAttribute{
									MarkdownDescription: "SNMPv3 username.",
									Computed:            true,
								},
								"auth_protocol": schema.StringAttribute{
									MarkdownDescription: "Authentication protocol.",
									Computed:            true,
								},
								"auth_key": schema.StringAttribute{
									MarkdownDescription: "Authentication key. Not returned by the API.",
									Computed:            true,
								},
								"privacy_protocol": schema.StringAttribute{
									MarkdownDescription: "Privacy protocol.",
									Computed:            true,
								},
								"privacy_key": schema.StringAttribute{
									MarkdownDescription: "Privacy key. Not returned by the API.",
									Computed:            true,
								},
							},
						},
						"snmp_write": schema.SingleNestedAttribute{
							MarkdownDescription: "SNMP write settings.",
							Computed:            true,
							Attributes: map[string]schema.Attribute{
								"default_vlan": schema.Int64Attribute{
									MarkdownDescription: "Default VLAN.",
									Computed:            true,
								},
								"snmp_version": schema.StringAttribute{
									MarkdownDescription: "SNMP version.",
									Computed:            true,
								},
								"community_string": schema.StringAttribute{
									MarkdownDescription: "Community string. Not returned by the API.",
									Computed:            true,
								},
								"security_level": schema.StringAttribute{
									MarkdownDescription: "Security level.",
									Computed:            true,
								},
								"user": schema.StringAttribute{
									MarkdownDescription: "SNMPv3 username.",
									Computed:            true,
								},
								"auth_protocol": schema.StringAttribute{
									MarkdownDescription: "Authentication protocol.",
									Computed:            true,
								},
								"auth_key": schema.StringAttribute{
									MarkdownDescription: "Authentication key. Not returned by the API.",
									Computed:            true,
								},
								"privacy_protocol": schema.StringAttribute{
									MarkdownDescription: "Privacy protocol.",
									Computed:            true,
								},
								"privacy_key": schema.StringAttribute{
									MarkdownDescription: "Privacy key. Not returned by the API.",
									Computed:            true,
								},
							},
						},
						"radsec_config": schema.SingleNestedAttribute{
							MarkdownDescription: "RadSec settings.",
							Computed:            true,
							Attributes: map[string]schema.Attribute{
								"serial_number": schema.StringAttribute{
									MarkdownDescription: "Serial Number of a Certificate.",
									Computed:            true,
								},
								"validate_cert": schema.StringAttribute{
									MarkdownDescription: "Certificate validation method.",
									Computed:            true,
								},
								"subject_dn": schema.StringAttribute{
									MarkdownDescription: "Issuer CA Certificate Subject DN.",
									Computed:            true,
								},
								"expiry_date": schema.StringAttribute{
									MarkdownDescription: "Issuer CA Certificate Expiry Date.",
									Computed:            true,
								},
								"cn_regex": schema.StringAttribute{
									MarkdownDescription: "Common Name Regular Expression String.",
									Computed:            true,
								},
								"san_regex": schema.StringAttribute{
									MarkdownDescription: "Subject Alternate Name Regular Expression String.",
									Computed:            true,
								},
								"src_override_ip": schema.StringAttribute{
									MarkdownDescription: "Source Override IP.",
									Computed:            true,
								},
							},
						},
						"cli_config": schema.SingleNestedAttribute{
							MarkdownDescription: "CLI Configuration details.",
							Computed:            true,
							Attributes: map[string]schema.Attribute{
								"type": schema.StringAttribute{
									MarkdownDescription: "Access type.",
									Computed:            true,
								},
								"port": schema.Int64Attribute{
									MarkdownDescription: "SSH/Telnet port number.",
									Computed:            true,
								},
								"username": schema.StringAttribute{
									MarkdownDescription: "CLI username.",
									Computed:            true,
								},
								"password": schema.StringAttribute{
									MarkdownDescription: "CLI password. Not returned by the API.",
									Computed:            true,
								},
								"username_prompt_regex": schema.StringAttribute{
									MarkdownDescription: "Username prompt regex.",
									Computed:            true,
								},
								"password_prompt_regex": schema.StringAttribute{
									MarkdownDescription: "Password prompt regex.",
									Computed:            true,
								},
								"command_prompt_regex": schema.StringAttribute{
									MarkdownDescription: "Command prompt regex.",
									Computed:            true,
								},
								"enable_prompt_regex": schema.StringAttribute{
									MarkdownDescription: "Enable prompt regex.",
									Computed:            true,
								},
								"enable_password": schema.StringAttribute{
									MarkdownDescription: "Enable password. Not returned by the API.",
									Computed:            true,
								},
							},
						},
						"onconnect_enforcement": schema.SingleNestedAttribute{
							MarkdownDescription: "OnConnect Enforcement settings.",
							Computed:            true,
							Attributes: map[string]schema.Attribute{
								"enabled": schema.BoolAttribute{
									MarkdownDescription: "Flag indicating if enabled.",
									Computed:            true,
								},
								"ports": schema.StringAttribute{
									MarkdownDescription: "Port names.",
									Computed:            true,
								},
							},
						},
					},
				},
			},
		},
	}
}

func (d *networkDevicesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *networkDevicesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state networkDevicesModel
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

	devices, err := d.client.GetNetworkDevices(ctx, filter, sort, offset, limit, calculateCount)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Network Devices",
			"Could not read network devices: "+err.Error(),
		)
		return
	}

	state.NetworkDevices = make([]networkDeviceModelItems, 0)
	if devices != nil && len(devices.Embedded.Items) > 0 {
		for _, device := range devices.Embedded.Items {
			item := networkDeviceModelItems{
				ID:            types.Int64Value(int64(device.ID)),
				Name:          types.StringValue(device.Name),
				Description:   types.StringValue(device.Description),
				IPAddress:     types.StringValue(device.IPAddress),
				VendorName:    types.StringValue(device.VendorName),
				VendorID:      types.Int64Value(device.VendorID),
				CoACapable:    types.BoolValue(device.CoACapable),
				CoAPort:       types.Int64Value(device.CoAPort),
				RadSecEnabled: types.BoolValue(device.RadSecEnabled),
			}

			if device.NADGroups != nil {
				nadGroupsList, diags := types.ListValueFrom(ctx, types.StringType, device.NADGroups)
				resp.Diagnostics.Append(diags...)
				item.NADGroups = nadGroupsList
			} else {
				item.NADGroups = types.ListNull(types.StringType)
			}

			if len(device.Attributes) > 0 {
				attrsMap, diags := types.MapValueFrom(ctx, types.StringType, device.Attributes)
				resp.Diagnostics.Append(diags...)
				item.Attributes = attrsMap
			} else {
				item.Attributes = types.MapNull(types.StringType)
			}

			var diags diag.Diagnostics
			item.SNMPRead, diags = flattenSNMPRead(ctx, device.SNMPRead)
			resp.Diagnostics.Append(diags...)
			item.SNMPWrite, diags = flattenSNMPWrite(ctx, device.SNMPWrite)
			resp.Diagnostics.Append(diags...)
			item.RadSecConfig, diags = flattenRadSecConfig(ctx, device.RadSecConfig)
			resp.Diagnostics.Append(diags...)
			item.CLIConfig, diags = flattenCLIConfig(ctx, device.CLIConfig)
			resp.Diagnostics.Append(diags...)
			item.OnConnectEnforcement, diags = flattenOnConnectEnforcement(ctx, device.OnConnectEnforcement)
			resp.Diagnostics.Append(diags...)

			state.NetworkDevices = append(state.NetworkDevices, item)
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
