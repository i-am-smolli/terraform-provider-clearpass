package provider

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var _ resource.Resource = &networkDeviceResource{}

type networkDeviceResource struct {
	client client.ClientInterface
}

// --- Terraform Models ---

type networkDeviceModel struct {
	ID                   types.Int64  `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	Description          types.String `tfsdk:"description"`
	IPAddress            types.String `tfsdk:"ip_address"`
	RadiusSecret         types.String `tfsdk:"radius_secret"`
	TacacsSecret         types.String `tfsdk:"tacacs_secret"`
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

type snmpReadModel struct {
	ForceRead       types.Bool   `tfsdk:"force_read"`
	ReadArpInfo     types.Bool   `tfsdk:"read_arp_info"`
	ZoneName        types.String `tfsdk:"zone_name"`
	SNMPVersion     types.String `tfsdk:"snmp_version"`
	CommunityString types.String `tfsdk:"community_string"`
	SecurityLevel   types.String `tfsdk:"security_level"`
	User            types.String `tfsdk:"user"`
	AuthProtocol    types.String `tfsdk:"auth_protocol"`
	AuthKey         types.String `tfsdk:"auth_key"`
	PrivacyProtocol types.String `tfsdk:"privacy_protocol"`
	PrivacyKey      types.String `tfsdk:"privacy_key"`
}

type snmpWriteModel struct {
	DefaultVLAN     types.Int64  `tfsdk:"default_vlan"`
	SNMPVersion     types.String `tfsdk:"snmp_version"`
	CommunityString types.String `tfsdk:"community_string"`
	SecurityLevel   types.String `tfsdk:"security_level"`
	User            types.String `tfsdk:"user"`
	AuthProtocol    types.String `tfsdk:"auth_protocol"`
	AuthKey         types.String `tfsdk:"auth_key"`
	PrivacyProtocol types.String `tfsdk:"privacy_protocol"`
	PrivacyKey      types.String `tfsdk:"privacy_key"`
}

type radSecConfigModel struct {
	SerialNumber  types.String `tfsdk:"serial_number"`
	ValidateCert  types.String `tfsdk:"validate_cert"`
	SubjectDN     types.String `tfsdk:"subject_dn"`
	ExpiryDate    types.String `tfsdk:"expiry_date"`
	CNRegex       types.String `tfsdk:"cn_regex"`
	SANRegex      types.String `tfsdk:"san_regex"`
	SrcOverrideIP types.String `tfsdk:"src_override_ip"`
}

type cliConfigModel struct {
	Type                types.String `tfsdk:"type"`
	Port                types.Int64  `tfsdk:"port"`
	Username            types.String `tfsdk:"username"`
	Password            types.String `tfsdk:"password"`
	UsernamePromptRegex types.String `tfsdk:"username_prompt_regex"`
	PasswordPromptRegex types.String `tfsdk:"password_prompt_regex"`
	CommandPromptRegex  types.String `tfsdk:"command_prompt_regex"`
	EnablePromptRegex   types.String `tfsdk:"enable_prompt_regex"`
	EnablePassword      types.String `tfsdk:"enable_password"`
}

type onConnectEnforcementModel struct {
	Enabled types.Bool   `tfsdk:"enabled"`
	Ports   types.String `tfsdk:"ports"`
}

// --- attrTypes helpers ---

func (m snmpReadModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"force_read":       types.BoolType,
		"read_arp_info":    types.BoolType,
		"zone_name":        types.StringType,
		"snmp_version":     types.StringType,
		"community_string": types.StringType,
		"security_level":   types.StringType,
		"user":             types.StringType,
		"auth_protocol":    types.StringType,
		"auth_key":         types.StringType,
		"privacy_protocol": types.StringType,
		"privacy_key":      types.StringType,
	}
}

func (m snmpWriteModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"default_vlan":     types.Int64Type,
		"snmp_version":     types.StringType,
		"community_string": types.StringType,
		"security_level":   types.StringType,
		"user":             types.StringType,
		"auth_protocol":    types.StringType,
		"auth_key":         types.StringType,
		"privacy_protocol": types.StringType,
		"privacy_key":      types.StringType,
	}
}

func (m radSecConfigModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"serial_number":   types.StringType,
		"validate_cert":   types.StringType,
		"subject_dn":      types.StringType,
		"expiry_date":     types.StringType,
		"cn_regex":        types.StringType,
		"san_regex":       types.StringType,
		"src_override_ip": types.StringType,
	}
}

func (m cliConfigModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type":                  types.StringType,
		"port":                  types.Int64Type,
		"username":              types.StringType,
		"password":              types.StringType,
		"username_prompt_regex": types.StringType,
		"password_prompt_regex": types.StringType,
		"command_prompt_regex":  types.StringType,
		"enable_prompt_regex":   types.StringType,
		"enable_password":       types.StringType,
	}
}

func (m onConnectEnforcementModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"enabled": types.BoolType,
		"ports":   types.StringType,
	}
}

// --- Resource Interface Implementation ---

func NewNetworkDeviceResource() resource.Resource {
	return &networkDeviceResource{}
}

func (r *networkDeviceResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_device"
}

func (r *networkDeviceResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a network device (NAD) in ClearPass Policy Manager. " +
			"Network devices represent switches, wireless controllers, VPN gateways, and other network equipment " +
			"that communicate with ClearPass via RADIUS, TACACS+, or other protocols.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description:   "Numeric ID of the network device assigned by ClearPass.",
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Description: "Name of the network device. Must be unique.",
				Required:    true,
			},
			"ip_address": schema.StringAttribute{
				Description: "IP or Subnet Address of the network device.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description:   "Description of the network device.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"radius_secret": schema.StringAttribute{
				Description: "RADIUS Shared Secret of the network device. This value is write-only and will not be read back from the API.",
				Optional:    true,
				Sensitive:   true,
				WriteOnly:   true,
			},
			"tacacs_secret": schema.StringAttribute{
				Description: "TACACS+ Shared Secret of the network device. This value is write-only and will not be read back from the API.",
				Optional:    true,
				Sensitive:   true,
				WriteOnly:   true,
			},
			"vendor_name": schema.StringAttribute{
				Description:   "Vendor Name of the network device (e.g., 'Cisco', 'Aruba', 'Juniper').",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"vendor_id": schema.Int64Attribute{
				Description:   "Vendor ID (IANA enterprise number) of the network device.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"coa_capable": schema.BoolAttribute{
				Description:   "Flag indicating if the network device is capable of RADIUS Change of Authorization (CoA).",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"coa_port": schema.Int64Attribute{
				Description:   "CoA port number of the network device.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"radsec_enabled": schema.BoolAttribute{
				Description:   "Flag indicating if the network device has RadSec enabled.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"nad_groups": schema.ListAttribute{
				Description: "List of NAD group names this device belongs to.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"attributes": schema.MapAttribute{
				Description: "Additional attributes (key/value pairs) stored with the network device.",
				Optional:    true,
				ElementType: types.StringType,
			},

			// --- Nested Blocks ---
			"snmp_read": schema.SingleNestedAttribute{
				Description: "SNMP read settings of the network device.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"force_read": schema.BoolAttribute{
						Description: "This field is deprecated.",
						Optional:    true,
					},
					"read_arp_info": schema.BoolAttribute{
						Description: "Enable to read ARP table from this device.",
						Optional:    true,
					},
					"zone_name": schema.StringAttribute{
						Description: "Policy Manager Zone name to be associated with the network device.",
						Optional:    true,
					},
					"snmp_version": schema.StringAttribute{
						Description: "SNMP version of the network device. Valid values: `V1`, `V2C`, `V3`.",
						Optional:    true,
					},
					"community_string": schema.StringAttribute{
						Description: "Community string of the network device. Write-only.",
						Optional:    true,
						Sensitive:   true,
						WriteOnly:   true,
					},
					"security_level": schema.StringAttribute{
						Description: "Security level of the network device. Valid values: `NOAUTH_NOPRIV`, `AUTH_NOPRIV`, `AUTH_PRIV`.",
						Optional:    true,
					},
					"user": schema.StringAttribute{
						Description: "SNMPv3 username.",
						Optional:    true,
					},
					"auth_protocol": schema.StringAttribute{
						Description: "Authentication protocol. Valid values: `MD5`, `SHA`.",
						Optional:    true,
					},
					"auth_key": schema.StringAttribute{
						Description: "Authentication key. Write-only.",
						Optional:    true,
						Sensitive:   true,
						WriteOnly:   true,
					},
					"privacy_protocol": schema.StringAttribute{
						Description: "Privacy protocol. Valid values: `DES_CBC`, `AES_128`.",
						Optional:    true,
					},
					"privacy_key": schema.StringAttribute{
						Description: "Privacy key. Write-only.",
						Optional:    true,
						Sensitive:   true,
						WriteOnly:   true,
					},
				},
			},
			"snmp_write": schema.SingleNestedAttribute{
				Description: "SNMP write settings of the network device.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"default_vlan": schema.Int64Attribute{
						Description: "Default VLAN for port when SNMP-enforced session expires.",
						Optional:    true,
					},
					"snmp_version": schema.StringAttribute{
						Description: "SNMP version. Valid values: `V1`, `V2C`, `V3`.",
						Optional:    true,
					},
					"community_string": schema.StringAttribute{
						Description: "Community string. Write-only.",
						Optional:    true,
						Sensitive:   true,
						WriteOnly:   true,
					},
					"security_level": schema.StringAttribute{
						Description: "Security level. Valid values: `NOAUTH_NOPRIV`, `AUTH_NOPRIV`, `AUTH_PRIV`.",
						Optional:    true,
					},
					"user": schema.StringAttribute{
						Description: "SNMPv3 username.",
						Optional:    true,
					},
					"auth_protocol": schema.StringAttribute{
						Description: "Authentication protocol. Valid values: `MD5`, `SHA`.",
						Optional:    true,
					},
					"auth_key": schema.StringAttribute{
						Description: "Authentication key. Write-only.",
						Optional:    true,
						Sensitive:   true,
						WriteOnly:   true,
					},
					"privacy_protocol": schema.StringAttribute{
						Description: "Privacy protocol. Valid values: `DES_CBC`, `AES_128`.",
						Optional:    true,
					},
					"privacy_key": schema.StringAttribute{
						Description: "Privacy key. Write-only.",
						Optional:    true,
						Sensitive:   true,
						WriteOnly:   true,
					},
				},
			},
			"radsec_config": schema.SingleNestedAttribute{
				Description: "RadSec settings of the network device.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"serial_number": schema.StringAttribute{
						Description: "Serial Number of a Certificate.",
						Optional:    true,
					},
					"validate_cert": schema.StringAttribute{
						Description: "Certificate validation method. Valid values: `NONE`, `CN_OR_SAN`, `RFC`.",
						Optional:    true,
					},
					"subject_dn": schema.StringAttribute{
						Description: "Issuer CA Certificate Subject DN.",
						Optional:    true,
					},
					"expiry_date": schema.StringAttribute{
						Description: "Issuer CA Certificate Expiry Date.",
						Optional:    true,
					},
					"cn_regex": schema.StringAttribute{
						Description: "Common Name Regular Expression String.",
						Optional:    true,
					},
					"san_regex": schema.StringAttribute{
						Description: "Subject Alternate Name Regular Expression String.",
						Optional:    true,
					},
					"src_override_ip": schema.StringAttribute{
						Description: "Source Override IP indicates the actual Source IP Address.",
						Optional:    true,
					},
				},
			},
			"cli_config": schema.SingleNestedAttribute{
				Description: "CLI Configuration details of the network device.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Description: "Access type of the network device. Valid values: `SSH`, `Telnet`.",
						Optional:    true,
					},
					"port": schema.Int64Attribute{
						Description: "SSH/Telnet port number.",
						Optional:    true,
					},
					"username": schema.StringAttribute{
						Description: "CLI username.",
						Optional:    true,
					},
					"password": schema.StringAttribute{
						Description: "CLI password. Write-only.",
						Optional:    true,
						Sensitive:   true,
						WriteOnly:   true,
					},
					"username_prompt_regex": schema.StringAttribute{
						Description: "Username prompt regex.",
						Optional:    true,
					},
					"password_prompt_regex": schema.StringAttribute{
						Description: "Password prompt regex.",
						Optional:    true,
					},
					"command_prompt_regex": schema.StringAttribute{
						Description: "Command prompt regex.",
						Optional:    true,
					},
					"enable_prompt_regex": schema.StringAttribute{
						Description: "Enable prompt regex.",
						Optional:    true,
					},
					"enable_password": schema.StringAttribute{
						Description: "Enable password. Write-only.",
						Optional:    true,
						Sensitive:   true,
						WriteOnly:   true,
					},
				},
			},
			"onconnect_enforcement": schema.SingleNestedAttribute{
				Description: "OnConnect Enforcement settings. Requires SNMP read configuration and Policy Manager Zone.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Description: "Flag indicating if OnConnect Enforcement is enabled.",
						Optional:    true,
					},
					"ports": schema.StringAttribute{
						Description: "Port names in CSV format (e.g. 'FastEthernet 1/0/10'). Empty string enables for all ports.",
						Optional:    true,
					},
				},
			},
		},
	}
}

func (r *networkDeviceResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Type", fmt.Sprintf("Expected ClientInterface, got: %T", req.ProviderData))
		return
	}
	r.client = c
}

// --- CRUD Methods ---

func (r *networkDeviceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan networkDeviceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// WriteOnly fields must be read from Config, not Plan (Plan nullifies them).
	var config networkDeviceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPayload := &client.NetworkDeviceCreate{
		Name:      plan.Name.ValueString(),
		IPAddress: plan.IPAddress.ValueString(),
	}
	if !plan.Description.IsNull() {
		apiPayload.Description = plan.Description.ValueString()
	}
	// Read secrets from config (WriteOnly)
	if !config.RadiusSecret.IsNull() {
		apiPayload.RadiusSecret = config.RadiusSecret.ValueString()
	}
	if !config.TacacsSecret.IsNull() {
		apiPayload.TacacsSecret = config.TacacsSecret.ValueString()
	}
	if !plan.VendorName.IsNull() {
		apiPayload.VendorName = plan.VendorName.ValueString()
	}
	if !plan.VendorID.IsNull() {
		v := plan.VendorID.ValueInt64()
		apiPayload.VendorID = &v
	}
	if !plan.CoACapable.IsNull() {
		v := plan.CoACapable.ValueBool()
		apiPayload.CoACapable = &v
	}
	if !plan.CoAPort.IsNull() {
		v := plan.CoAPort.ValueInt64()
		apiPayload.CoAPort = &v
	}
	if !plan.RadSecEnabled.IsNull() {
		v := plan.RadSecEnabled.ValueBool()
		apiPayload.RadSecEnabled = &v
	}
	if !plan.NADGroups.IsNull() {
		var groups []string
		resp.Diagnostics.Append(plan.NADGroups.ElementsAs(ctx, &groups, false)...)
		apiPayload.NADGroups = groups
	}
	if !plan.Attributes.IsNull() {
		var attrs map[string]string
		resp.Diagnostics.Append(plan.Attributes.ElementsAs(ctx, &attrs, false)...)
		apiPayload.Attributes = attrs
	}

	// Use config for nested blocks (they contain WriteOnly fields)
	apiPayload.SNMPRead = expandSNMPRead(ctx, config.SNMPRead, &resp.Diagnostics)
	apiPayload.SNMPWrite = expandSNMPWrite(ctx, config.SNMPWrite, &resp.Diagnostics)
	apiPayload.RadSecConfig = expandRadSecConfig(ctx, plan.RadSecConfig, &resp.Diagnostics)
	apiPayload.CLIConfig = expandCLIConfig(ctx, config.CLIConfig, &resp.Diagnostics)
	apiPayload.OnConnectEnforcement = expandOnConnectEnforcement(ctx, plan.OnConnectEnforcement, &resp.Diagnostics)

	if resp.Diagnostics.HasError() {
		return
	}

	created, err := r.client.CreateNetworkDevice(ctx, apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to create network device: %s", err))
		return
	}

	mapNetworkDeviceResultToState(ctx, created, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *networkDeviceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state networkDeviceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	device, err := r.client.GetNetworkDevice(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to read network device: %s", err))
		return
	}
	if device == nil {
		resp.Diagnostics.AddWarning("Resource Not Found", "Network device not found, removing from state.")
		resp.State.RemoveResource(ctx)
		return
	}

	mapNetworkDeviceResultToState(ctx, device, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *networkDeviceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan networkDeviceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// WriteOnly fields must be read from Config, not Plan (Plan nullifies them).
	var config networkDeviceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPayload := &client.NetworkDeviceUpdate{}
	if !plan.Name.IsUnknown() {
		apiPayload.Name = plan.Name.ValueString()
	}
	if !plan.IPAddress.IsUnknown() {
		apiPayload.IPAddress = plan.IPAddress.ValueString()
	}
	if !plan.Description.IsUnknown() {
		apiPayload.Description = plan.Description.ValueString()
	}
	// Read secrets from config (WriteOnly)
	if !config.RadiusSecret.IsNull() {
		apiPayload.RadiusSecret = config.RadiusSecret.ValueString()
	}
	if !config.TacacsSecret.IsNull() {
		apiPayload.TacacsSecret = config.TacacsSecret.ValueString()
	}
	if !plan.VendorName.IsUnknown() && !plan.VendorName.IsNull() {
		apiPayload.VendorName = plan.VendorName.ValueString()
	}
	if !plan.VendorID.IsUnknown() && !plan.VendorID.IsNull() {
		v := plan.VendorID.ValueInt64()
		apiPayload.VendorID = &v
	}
	if !plan.CoACapable.IsUnknown() && !plan.CoACapable.IsNull() {
		v := plan.CoACapable.ValueBool()
		apiPayload.CoACapable = &v
	}
	if !plan.CoAPort.IsUnknown() && !plan.CoAPort.IsNull() {
		v := plan.CoAPort.ValueInt64()
		apiPayload.CoAPort = &v
	}
	if !plan.RadSecEnabled.IsUnknown() && !plan.RadSecEnabled.IsNull() {
		v := plan.RadSecEnabled.ValueBool()
		apiPayload.RadSecEnabled = &v
	}
	if !plan.NADGroups.IsNull() && !plan.NADGroups.IsUnknown() {
		var groups []string
		resp.Diagnostics.Append(plan.NADGroups.ElementsAs(ctx, &groups, false)...)
		apiPayload.NADGroups = groups
	}
	if !plan.Attributes.IsNull() && !plan.Attributes.IsUnknown() {
		var attrs map[string]string
		resp.Diagnostics.Append(plan.Attributes.ElementsAs(ctx, &attrs, false)...)
		apiPayload.Attributes = attrs
	}

	// Use config for nested blocks that contain WriteOnly fields
	apiPayload.SNMPRead = expandSNMPRead(ctx, config.SNMPRead, &resp.Diagnostics)
	apiPayload.SNMPWrite = expandSNMPWrite(ctx, config.SNMPWrite, &resp.Diagnostics)
	apiPayload.RadSecConfig = expandRadSecConfig(ctx, plan.RadSecConfig, &resp.Diagnostics)
	apiPayload.CLIConfig = expandCLIConfig(ctx, config.CLIConfig, &resp.Diagnostics)
	apiPayload.OnConnectEnforcement = expandOnConnectEnforcement(ctx, plan.OnConnectEnforcement, &resp.Diagnostics)

	if resp.Diagnostics.HasError() {
		return
	}

	updated, err := r.client.UpdateNetworkDevice(ctx, int(plan.ID.ValueInt64()), apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to update network device: %s", err))
		return
	}

	mapNetworkDeviceResultToState(ctx, updated, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *networkDeviceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state networkDeviceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.DeleteNetworkDevice(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to delete network device: %s", err))
	}
}

func (r *networkDeviceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	numericID, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected a numeric ID for import, got %q. Error: %s", req.ID, err.Error()),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), numericID)...)
}

// --- State Mapping Helper ---

func mapNetworkDeviceResultToState(ctx context.Context, device *client.NetworkDeviceResult, state *networkDeviceModel, diags *diag.Diagnostics) {
	state.ID = types.Int64Value(int64(device.ID))
	state.Name = types.StringValue(device.Name)
	state.IPAddress = types.StringValue(device.IPAddress)
	state.Description = types.StringValue(device.Description)
	state.VendorName = types.StringValue(device.VendorName)
	state.VendorID = types.Int64Value(device.VendorID)
	state.CoACapable = types.BoolValue(device.CoACapable)
	state.CoAPort = types.Int64Value(device.CoAPort)
	state.RadSecEnabled = types.BoolValue(device.RadSecEnabled)

	// NAD Groups
	if device.NADGroups != nil {
		nadGroupsList, d := types.ListValueFrom(ctx, types.StringType, device.NADGroups)
		diags.Append(d...)
		state.NADGroups = nadGroupsList
	} else {
		state.NADGroups = types.ListNull(types.StringType)
	}

	// Attributes
	if device.Attributes != nil && len(device.Attributes) > 0 {
		attrsMap, d := types.MapValueFrom(ctx, types.StringType, device.Attributes)
		diags.Append(d...)
		state.Attributes = attrsMap
	} else {
		state.Attributes = types.MapNull(types.StringType)
	}

	// Nested objects
	var d diag.Diagnostics
	state.SNMPRead, d = flattenSNMPRead(ctx, device.SNMPRead)
	diags.Append(d...)
	state.SNMPWrite, d = flattenSNMPWrite(ctx, device.SNMPWrite)
	diags.Append(d...)
	state.RadSecConfig, d = flattenRadSecConfig(ctx, device.RadSecConfig)
	diags.Append(d...)
	state.CLIConfig, d = flattenCLIConfig(ctx, device.CLIConfig)
	diags.Append(d...)
	state.OnConnectEnforcement, d = flattenOnConnectEnforcement(ctx, device.OnConnectEnforcement)
	diags.Append(d...)
}

// --- Expand Helpers (Terraform → API) ---

func expandSNMPRead(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *client.SNMPReadSettings {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var model snmpReadModel
	diags.Append(obj.As(ctx, &model, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}
	api := &client.SNMPReadSettings{}
	if !model.ForceRead.IsNull() {
		v := model.ForceRead.ValueBool()
		api.ForceRead = &v
	}
	if !model.ReadArpInfo.IsNull() {
		v := model.ReadArpInfo.ValueBool()
		api.ReadArpInfo = &v
	}
	if !model.ZoneName.IsNull() {
		api.ZoneName = model.ZoneName.ValueString()
	}
	if !model.SNMPVersion.IsNull() {
		api.SNMPVersion = model.SNMPVersion.ValueString()
	}
	if !model.CommunityString.IsNull() {
		api.CommunityString = model.CommunityString.ValueString()
	}
	if !model.SecurityLevel.IsNull() {
		api.SecurityLevel = model.SecurityLevel.ValueString()
	}
	if !model.User.IsNull() {
		api.User = model.User.ValueString()
	}
	if !model.AuthProtocol.IsNull() {
		api.AuthProtocol = model.AuthProtocol.ValueString()
	}
	if !model.AuthKey.IsNull() {
		api.AuthKey = model.AuthKey.ValueString()
	}
	if !model.PrivacyProtocol.IsNull() {
		api.PrivacyProtocol = model.PrivacyProtocol.ValueString()
	}
	if !model.PrivacyKey.IsNull() {
		api.PrivacyKey = model.PrivacyKey.ValueString()
	}
	return api
}

func expandSNMPWrite(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *client.SNMPWriteSettings {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var model snmpWriteModel
	diags.Append(obj.As(ctx, &model, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}
	api := &client.SNMPWriteSettings{}
	if !model.DefaultVLAN.IsNull() {
		v := model.DefaultVLAN.ValueInt64()
		api.DefaultVLAN = &v
	}
	if !model.SNMPVersion.IsNull() {
		api.SNMPVersion = model.SNMPVersion.ValueString()
	}
	if !model.CommunityString.IsNull() {
		api.CommunityString = model.CommunityString.ValueString()
	}
	if !model.SecurityLevel.IsNull() {
		api.SecurityLevel = model.SecurityLevel.ValueString()
	}
	if !model.User.IsNull() {
		api.User = model.User.ValueString()
	}
	if !model.AuthProtocol.IsNull() {
		api.AuthProtocol = model.AuthProtocol.ValueString()
	}
	if !model.AuthKey.IsNull() {
		api.AuthKey = model.AuthKey.ValueString()
	}
	if !model.PrivacyProtocol.IsNull() {
		api.PrivacyProtocol = model.PrivacyProtocol.ValueString()
	}
	if !model.PrivacyKey.IsNull() {
		api.PrivacyKey = model.PrivacyKey.ValueString()
	}
	return api
}

func expandRadSecConfig(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *client.RadSecSettings {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var model radSecConfigModel
	diags.Append(obj.As(ctx, &model, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}
	api := &client.RadSecSettings{}
	if !model.SerialNumber.IsNull() {
		api.SerialNumber = model.SerialNumber.ValueString()
	}
	if !model.ValidateCert.IsNull() {
		api.ValidateCert = model.ValidateCert.ValueString()
	}
	if !model.SubjectDN.IsNull() {
		api.SubjectDN = model.SubjectDN.ValueString()
	}
	if !model.ExpiryDate.IsNull() {
		api.ExpiryDate = model.ExpiryDate.ValueString()
	}
	if !model.CNRegex.IsNull() {
		api.CNRegex = model.CNRegex.ValueString()
	}
	if !model.SANRegex.IsNull() {
		api.SANRegex = model.SANRegex.ValueString()
	}
	if !model.SrcOverrideIP.IsNull() {
		api.SrcOverrideIP = model.SrcOverrideIP.ValueString()
	}
	return api
}

func expandCLIConfig(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *client.CLISettings {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var model cliConfigModel
	diags.Append(obj.As(ctx, &model, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}
	api := &client.CLISettings{}
	if !model.Type.IsNull() {
		api.Type = model.Type.ValueString()
	}
	if !model.Port.IsNull() {
		v := model.Port.ValueInt64()
		api.Port = &v
	}
	if !model.Username.IsNull() {
		api.Username = model.Username.ValueString()
	}
	if !model.Password.IsNull() {
		api.Password = model.Password.ValueString()
	}
	if !model.UsernamePromptRegex.IsNull() {
		api.UsernamePromptRegex = model.UsernamePromptRegex.ValueString()
	}
	if !model.PasswordPromptRegex.IsNull() {
		api.PasswordPromptRegex = model.PasswordPromptRegex.ValueString()
	}
	if !model.CommandPromptRegex.IsNull() {
		api.CommandPromptRegex = model.CommandPromptRegex.ValueString()
	}
	if !model.EnablePromptRegex.IsNull() {
		api.EnablePromptRegex = model.EnablePromptRegex.ValueString()
	}
	if !model.EnablePassword.IsNull() {
		api.EnablePassword = model.EnablePassword.ValueString()
	}
	return api
}

func expandOnConnectEnforcement(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *client.OnConnectEnforcementSettings {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var model onConnectEnforcementModel
	diags.Append(obj.As(ctx, &model, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}
	api := &client.OnConnectEnforcementSettings{}
	if !model.Enabled.IsNull() {
		v := model.Enabled.ValueBool()
		api.Enabled = &v
	}
	if !model.Ports.IsNull() {
		api.Ports = model.Ports.ValueString()
	}
	return api
}

// --- Flatten Helpers (API → Terraform) ---

func flattenSNMPRead(ctx context.Context, api *client.SNMPReadSettings) (types.Object, diag.Diagnostics) {
	if api == nil {
		return types.ObjectNull(snmpReadModel{}.attrTypes()), nil
	}
	model := snmpReadModel{
		ForceRead:       types.BoolNull(),
		ReadArpInfo:     types.BoolNull(),
		ZoneName:        types.StringNull(),
		SNMPVersion:     types.StringNull(),
		CommunityString: types.StringNull(), // WriteOnly — never read back
		SecurityLevel:   types.StringNull(),
		User:            types.StringNull(),
		AuthProtocol:    types.StringNull(),
		AuthKey:         types.StringNull(), // WriteOnly
		PrivacyProtocol: types.StringNull(),
		PrivacyKey:      types.StringNull(), // WriteOnly
	}
	if api.ForceRead != nil {
		model.ForceRead = types.BoolValue(*api.ForceRead)
	}
	if api.ReadArpInfo != nil {
		model.ReadArpInfo = types.BoolValue(*api.ReadArpInfo)
	}
	if api.ZoneName != "" {
		model.ZoneName = types.StringValue(api.ZoneName)
	}
	if api.SNMPVersion != "" {
		model.SNMPVersion = types.StringValue(api.SNMPVersion)
	}
	if api.SecurityLevel != "" {
		model.SecurityLevel = types.StringValue(api.SecurityLevel)
	}
	if api.User != "" {
		model.User = types.StringValue(api.User)
	}
	if api.AuthProtocol != "" {
		model.AuthProtocol = types.StringValue(api.AuthProtocol)
	}
	if api.PrivacyProtocol != "" {
		model.PrivacyProtocol = types.StringValue(api.PrivacyProtocol)
	}
	return types.ObjectValueFrom(ctx, snmpReadModel{}.attrTypes(), model)
}

func flattenSNMPWrite(ctx context.Context, api *client.SNMPWriteSettings) (types.Object, diag.Diagnostics) {
	if api == nil {
		return types.ObjectNull(snmpWriteModel{}.attrTypes()), nil
	}
	model := snmpWriteModel{
		DefaultVLAN:     types.Int64Null(),
		SNMPVersion:     types.StringNull(),
		CommunityString: types.StringNull(), // WriteOnly
		SecurityLevel:   types.StringNull(),
		User:            types.StringNull(),
		AuthProtocol:    types.StringNull(),
		AuthKey:         types.StringNull(), // WriteOnly
		PrivacyProtocol: types.StringNull(),
		PrivacyKey:      types.StringNull(), // WriteOnly
	}
	if api.DefaultVLAN != nil {
		model.DefaultVLAN = types.Int64Value(*api.DefaultVLAN)
	}
	if api.SNMPVersion != "" {
		model.SNMPVersion = types.StringValue(api.SNMPVersion)
	}
	if api.SecurityLevel != "" {
		model.SecurityLevel = types.StringValue(api.SecurityLevel)
	}
	if api.User != "" {
		model.User = types.StringValue(api.User)
	}
	if api.AuthProtocol != "" {
		model.AuthProtocol = types.StringValue(api.AuthProtocol)
	}
	if api.PrivacyProtocol != "" {
		model.PrivacyProtocol = types.StringValue(api.PrivacyProtocol)
	}
	return types.ObjectValueFrom(ctx, snmpWriteModel{}.attrTypes(), model)
}

func flattenRadSecConfig(ctx context.Context, api *client.RadSecSettings) (types.Object, diag.Diagnostics) {
	if api == nil {
		return types.ObjectNull(radSecConfigModel{}.attrTypes()), nil
	}
	model := radSecConfigModel{
		SerialNumber:  types.StringNull(),
		ValidateCert:  types.StringNull(),
		SubjectDN:     types.StringNull(),
		ExpiryDate:    types.StringNull(),
		CNRegex:       types.StringNull(),
		SANRegex:      types.StringNull(),
		SrcOverrideIP: types.StringNull(),
	}
	if api.SerialNumber != "" {
		model.SerialNumber = types.StringValue(api.SerialNumber)
	}
	if api.ValidateCert != "" {
		model.ValidateCert = types.StringValue(api.ValidateCert)
	}
	if api.SubjectDN != "" {
		model.SubjectDN = types.StringValue(api.SubjectDN)
	}
	if api.ExpiryDate != "" {
		model.ExpiryDate = types.StringValue(api.ExpiryDate)
	}
	if api.CNRegex != "" {
		model.CNRegex = types.StringValue(api.CNRegex)
	}
	if api.SANRegex != "" {
		model.SANRegex = types.StringValue(api.SANRegex)
	}
	if api.SrcOverrideIP != "" {
		model.SrcOverrideIP = types.StringValue(api.SrcOverrideIP)
	}
	return types.ObjectValueFrom(ctx, radSecConfigModel{}.attrTypes(), model)
}

func flattenCLIConfig(ctx context.Context, api *client.CLISettings) (types.Object, diag.Diagnostics) {
	if api == nil {
		return types.ObjectNull(cliConfigModel{}.attrTypes()), nil
	}
	model := cliConfigModel{
		Type:                types.StringNull(),
		Port:                types.Int64Null(),
		Username:            types.StringNull(),
		Password:            types.StringNull(), // WriteOnly
		UsernamePromptRegex: types.StringNull(),
		PasswordPromptRegex: types.StringNull(),
		CommandPromptRegex:  types.StringNull(),
		EnablePromptRegex:   types.StringNull(),
		EnablePassword:      types.StringNull(), // WriteOnly
	}
	if api.Type != "" {
		model.Type = types.StringValue(api.Type)
	}
	if api.Port != nil {
		model.Port = types.Int64Value(*api.Port)
	}
	if api.Username != "" {
		model.Username = types.StringValue(api.Username)
	}
	if api.UsernamePromptRegex != "" {
		model.UsernamePromptRegex = types.StringValue(api.UsernamePromptRegex)
	}
	if api.PasswordPromptRegex != "" {
		model.PasswordPromptRegex = types.StringValue(api.PasswordPromptRegex)
	}
	if api.CommandPromptRegex != "" {
		model.CommandPromptRegex = types.StringValue(api.CommandPromptRegex)
	}
	if api.EnablePromptRegex != "" {
		model.EnablePromptRegex = types.StringValue(api.EnablePromptRegex)
	}
	return types.ObjectValueFrom(ctx, cliConfigModel{}.attrTypes(), model)
}

func flattenOnConnectEnforcement(ctx context.Context, api *client.OnConnectEnforcementSettings) (types.Object, diag.Diagnostics) {
	if api == nil {
		return types.ObjectNull(onConnectEnforcementModel{}.attrTypes()), nil
	}
	model := onConnectEnforcementModel{
		Enabled: types.BoolNull(),
		Ports:   types.StringNull(),
	}
	if api.Enabled != nil {
		model.Enabled = types.BoolValue(*api.Enabled)
	}
	if api.Ports != "" {
		model.Ports = types.StringValue(api.Ports)
	}
	return types.ObjectValueFrom(ctx, onConnectEnforcementModel{}.attrTypes(), model)
}
