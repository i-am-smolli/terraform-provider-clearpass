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
	_ datasource.DataSource              = &networkDeviceDataSource{}
	_ datasource.DataSourceWithConfigure = &networkDeviceDataSource{}
)

func NewNetworkDeviceDataSource() datasource.DataSource {
	return &networkDeviceDataSource{}
}

type networkDeviceDataSource struct {
	client client.ClientInterface
}

type networkDeviceDataSourceModel struct {
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

func (d *networkDeviceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_device"
}

func (d *networkDeviceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves the details of a specific network device (NAD) in ClearPass by its numeric ID or name. " +
			"Network devices represent switches, wireless controllers, VPN gateways, and other network equipment " +
			"that communicate with ClearPass via RADIUS, TACACS+, or other protocols.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				MarkdownDescription: "Numeric ID of the network device. Specify either `id` or `name` to look up a device.",
				Optional:            true,
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Name of the network device. Specify either `id` or `name` to look up a device.",
				Optional:            true,
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
				MarkdownDescription: "Vendor ID (IANA enterprise number) of the network device.",
				Computed:            true,
			},
			"coa_capable": schema.BoolAttribute{
				MarkdownDescription: "Flag indicating if the network device is capable of RADIUS Change of Authorization (CoA).",
				Computed:            true,
			},
			"coa_port": schema.Int64Attribute{
				MarkdownDescription: "CoA port number of the network device.",
				Computed:            true,
			},
			"radsec_enabled": schema.BoolAttribute{
				MarkdownDescription: "Flag indicating if the network device has RadSec enabled.",
				Computed:            true,
			},
			"nad_groups": schema.ListAttribute{
				MarkdownDescription: "List of NAD group names this device belongs to.",
				Computed:            true,
				ElementType:         types.StringType,
			},
			"attributes": schema.MapAttribute{
				MarkdownDescription: "Additional attributes (key/value pairs) stored with the network device.",
				Computed:            true,
				ElementType:         types.StringType,
			},

			// --- Nested Read-Only Blocks ---
			"snmp_read": schema.SingleNestedAttribute{
				MarkdownDescription: "SNMP read settings of the network device.",
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
				MarkdownDescription: "SNMP write settings of the network device.",
				Computed:            true,
				Attributes: map[string]schema.Attribute{
					"default_vlan": schema.Int64Attribute{
						MarkdownDescription: "Default VLAN for port when SNMP-enforced session expires.",
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
				MarkdownDescription: "RadSec settings of the network device.",
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
						MarkdownDescription: "Source Override IP indicates the actual Source IP Address.",
						Computed:            true,
					},
				},
			},
			"cli_config": schema.SingleNestedAttribute{
				MarkdownDescription: "CLI Configuration details of the network device.",
				Computed:            true,
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						MarkdownDescription: "Access type of the network device (SSH or Telnet).",
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
						MarkdownDescription: "Flag indicating if OnConnect Enforcement is enabled.",
						Computed:            true,
					},
					"ports": schema.StringAttribute{
						MarkdownDescription: "Port names in CSV format.",
						Computed:            true,
					},
				},
			},
		},
	}
}

func (d *networkDeviceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *networkDeviceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state networkDeviceDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.ID.IsNull() && state.Name.IsNull() {
		resp.Diagnostics.AddError(
			"Missing Configuration",
			"Either 'id' or 'name' must be configured to read a network device.",
		)
		return
	}

	var device *client.NetworkDeviceResult
	var err error

	if !state.ID.IsNull() {
		device, err = d.client.GetNetworkDevice(ctx, int(state.ID.ValueInt64()))
	} else {
		device, err = d.client.GetNetworkDeviceByName(ctx, state.Name.ValueString())
	}

	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Network Device",
			"Could not read network device: "+err.Error(),
		)
		return
	}

	if device == nil {
		if !state.ID.IsNull() {
			resp.Diagnostics.AddError(
				"ClearPass Network Device Not Found",
				fmt.Sprintf("Network device with ID %d not found", state.ID.ValueInt64()),
			)
		} else {
			resp.Diagnostics.AddError(
				"ClearPass Network Device Not Found",
				fmt.Sprintf("Network device with name '%s' not found", state.Name.ValueString()),
			)
		}
		return
	}

	// Map API result to data source model
	state.ID = types.Int64Value(int64(device.ID))
	state.Name = types.StringValue(device.Name)
	state.Description = types.StringValue(device.Description)
	state.IPAddress = types.StringValue(device.IPAddress)
	state.VendorName = types.StringValue(device.VendorName)
	state.VendorID = types.Int64Value(device.VendorID)
	state.CoACapable = types.BoolValue(device.CoACapable)
	state.CoAPort = types.Int64Value(device.CoAPort)
	state.RadSecEnabled = types.BoolValue(device.RadSecEnabled)

	// NAD Groups
	if device.NADGroups != nil {
		nadGroupsList, diags := types.ListValueFrom(ctx, types.StringType, device.NADGroups)
		resp.Diagnostics.Append(diags...)
		state.NADGroups = nadGroupsList
	} else {
		state.NADGroups = types.ListNull(types.StringType)
	}

	// Attributes
	if device.Attributes != nil && len(device.Attributes) > 0 {
		attrsMap, diags := types.MapValueFrom(ctx, types.StringType, device.Attributes)
		resp.Diagnostics.Append(diags...)
		state.Attributes = attrsMap
	} else {
		state.Attributes = types.MapNull(types.StringType)
	}

	// Nested objects — reuse flatten helpers from the resource
	var diags diag.Diagnostics
	state.SNMPRead, diags = flattenSNMPRead(ctx, device.SNMPRead)
	resp.Diagnostics.Append(diags...)
	state.SNMPWrite, diags = flattenSNMPWrite(ctx, device.SNMPWrite)
	resp.Diagnostics.Append(diags...)
	state.RadSecConfig, diags = flattenRadSecConfig(ctx, device.RadSecConfig)
	resp.Diagnostics.Append(diags...)
	state.CLIConfig, diags = flattenCLIConfig(ctx, device.CLIConfig)
	resp.Diagnostics.Append(diags...)
	state.OnConnectEnforcement, diags = flattenOnConnectEnforcement(ctx, device.OnConnectEnforcement)
	resp.Diagnostics.Append(diags...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
