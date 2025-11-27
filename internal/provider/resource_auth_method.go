package provider

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &AuthMethodResource{}
var _ resource.ResourceWithImportState = &AuthMethodResource{}

func NewAuthMethodResource() resource.Resource {
	return &AuthMethodResource{}
}

// AuthMethodResource defines the resource implementation.
type AuthMethodResource struct {
	client client.ClientInterface
}

// AuthMethodResourceModel describes the resource data model.
type AuthMethodResourceModel struct {
	ID           types.String             `tfsdk:"id"`
	Name         types.String             `tfsdk:"name"`
	Description  types.String             `tfsdk:"description"`
	MethodType   types.String             `tfsdk:"method_type"`
	InnerMethods types.List               `tfsdk:"inner_methods"`
	Details      []AuthMethodDetailsModel `tfsdk:"details"`
}

type AuthMethodDetailsModel struct {
	TunnelPACLifetime                 types.Int64  `tfsdk:"tunnel_pac_lifetime"`
	TunnelPACLifetimeUnits            types.String `tfsdk:"tunnel_pac_lifetime_units"`
	UserAuthPACEnable                 types.Bool   `tfsdk:"user_auth_pac_enable"`
	UserAuthPACLifetime               types.Int64  `tfsdk:"user_auth_pac_lifetime"`
	UserAuthPACLifetimeUnits          types.String `tfsdk:"user_auth_pac_lifetime_units"`
	MachinePACEnable                  types.Bool   `tfsdk:"machine_pac_enable"`
	MachinePACLifetime                types.Int64  `tfsdk:"machine_pac_lifetime"`
	MachinePACLifetimeUnits           types.String `tfsdk:"machine_pac_lifetime_units"`
	PosturePACEnable                  types.Bool   `tfsdk:"posture_pac_enable"`
	PosturePACLifetime                types.Int64  `tfsdk:"posture_pac_lifetime"`
	PosturePACLifetimeUnits           types.String `tfsdk:"posture_pac_lifetime_units"`
	AllowAnonymousProvisioning        types.Bool   `tfsdk:"allow_anonymous_provisioning"`
	AuthProvisioningRequireClientCert types.Bool   `tfsdk:"auth_provisioning_require_client_cert"`
	ClientCertificateAuth             types.Bool   `tfsdk:"client_certificate_auth"`
	AllowAuthenticatedProvisioning    types.Bool   `tfsdk:"allow_authenticated_provisioning"`
	CertificateComparison             types.String `tfsdk:"certificate_comparison"`
	SessionTimeout                    types.Int64  `tfsdk:"session_timeout"`
	SessionCacheEnable                types.Bool   `tfsdk:"session_cache_enable"`
	Challenge                         types.String `tfsdk:"challenge"`
	AllowFastReconnect                types.Bool   `tfsdk:"allow_fast_reconnect"`
	NAPSupportEnable                  types.Bool   `tfsdk:"nap_support_enable"`
	EnforceCryptoBinding              types.String `tfsdk:"enforce_crypto_binding"`
	PublicPassword                    types.String `tfsdk:"public_password"`
	PublicUsername                    types.String `tfsdk:"public_username"`
	GroupName                         types.String `tfsdk:"group_name"`
	ServerID                          types.String `tfsdk:"server_id"`
	AutzRequired                      types.Bool   `tfsdk:"autz_required"`
	OCSPEnable                        types.String `tfsdk:"ocsp_enable"`
	OCSPURL                           types.String `tfsdk:"ocsp_url"`
	OverrideCertURL                   types.Bool   `tfsdk:"override_cert_url"`
	EncryptionScheme                  types.String `tfsdk:"encryption_scheme"`
	AllowUnknownClients               types.Bool   `tfsdk:"allow_unknown_clients"`
	PassResetFlow                     types.String `tfsdk:"pass_reset_flow"`
	NoOfRetries                       types.Int64  `tfsdk:"no_of_retries"`
}

func (r *AuthMethodResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_auth_method"
}

func (r *AuthMethodResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Authentication Method Resource",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Numeric ID of the auth method",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the auth method",
			},
			"description": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Description of the auth method",
			},
			"method_type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Type of the auth method",
			},
			"inner_methods": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "List of inner methods of the auth method",
			},
		},
		Blocks: map[string]schema.Block{
			"details": schema.ListNestedBlock{
				MarkdownDescription: "Details of the auth method",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"tunnel_pac_lifetime": schema.Int64Attribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Tunnel PAC Expire Time",
						},
						"tunnel_pac_lifetime_units": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Tunnel PAC Expire Time Units",
						},
						"user_auth_pac_enable": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Authorization PAC",
						},
						"user_auth_pac_lifetime": schema.Int64Attribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Authorization PAC Expire Time",
						},
						"user_auth_pac_lifetime_units": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Authorization PAC Expire Time Units",
						},
						"machine_pac_enable": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Machine PAC",
						},
						"machine_pac_lifetime": schema.Int64Attribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Machine PAC Expire Time",
						},
						"machine_pac_lifetime_units": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Machine PAC Expire Time Units",
						},
						"posture_pac_enable": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Posture PAC",
						},
						"posture_pac_lifetime": schema.Int64Attribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Posture PAC Expire Time",
						},
						"posture_pac_lifetime_units": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Posture PAC Expire Time Units",
						},
						"allow_anonymous_provisioning": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Allow anonymous mode (requires no server certificate)",
						},
						"auth_provisioning_require_client_cert": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Require end-host certificate for provisioning",
						},
						"client_certificate_auth": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "End-Host Authentication",
						},
						"allow_authenticated_provisioning": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Allow authenticated mode (requires server certificate)",
						},
						"certificate_comparison": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Certificate Comparison",
						},
						"session_timeout": schema.Int64Attribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Session Timeout",
						},
						"session_cache_enable": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Session Resumption",
						},
						"challenge": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Challenge",
						},
						"allow_fast_reconnect": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Fast Reconnect",
						},
						"nap_support_enable": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Microsoft NAP Support",
						},
						"enforce_crypto_binding": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Cryptobinding",
						},
						"public_password": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Public Password",
						},
						"public_username": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Public Username",
						},
						"group_name": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Group",
						},
						"server_id": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Server Id",
						},
						"autz_required": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Authorization Required",
						},
						"ocsp_enable": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Verify Certificate using OCSP",
						},
						"ocsp_url": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "OCSP URL",
						},
						"override_cert_url": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Override OCSP URL from Client",
						},
						"encryption_scheme": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Enable Aruba-SSO",
						},
						"allow_unknown_clients": schema.BoolAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Allow Unknown End-Hosts",
						},
						"pass_reset_flow": schema.StringAttribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Password reset sends in",
						},
						"no_of_retries": schema.Int64Attribute{
							Optional:            true,
							Computed:            true,
							MarkdownDescription: "Number of retries",
						},
					},
				},
			},
		},
	}
}

func (r *AuthMethodResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected client.ClientInterface, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *AuthMethodResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AuthMethodResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert model to API client struct
	authMethodCreate := &client.AuthMethodCreate{
		Name:        data.Name.ValueString(),
		Description: data.Description.ValueString(),
		MethodType:  data.MethodType.ValueString(),
	}

	if !data.InnerMethods.IsNull() && !data.InnerMethods.IsUnknown() {
		var innerMethods []string
		data.InnerMethods.ElementsAs(ctx, &innerMethods, false)
		authMethodCreate.InnerMethods = innerMethods
	}

	if len(data.Details) > 0 {
		details := data.Details[0]
		authMethodCreate.Details = &client.AuthMethodDetails{
			TunnelPACLifetime:                 client.FlexInt(details.TunnelPACLifetime.ValueInt64()),
			TunnelPACLifetimeUnits:            details.TunnelPACLifetimeUnits.ValueString(),
			UserAuthPACEnable:                 client.FlexBool(details.UserAuthPACEnable.ValueBool()),
			UserAuthPACLifetime:               client.FlexInt(details.UserAuthPACLifetime.ValueInt64()),
			UserAuthPACLifetimeUnits:          details.UserAuthPACLifetimeUnits.ValueString(),
			MachinePACEnable:                  client.FlexBool(details.MachinePACEnable.ValueBool()),
			MachinePACLifetime:                client.FlexInt(details.MachinePACLifetime.ValueInt64()),
			MachinePACLifetimeUnits:           details.MachinePACLifetimeUnits.ValueString(),
			PosturePACEnable:                  client.FlexBool(details.PosturePACEnable.ValueBool()),
			PosturePACLifetime:                client.FlexInt(details.PosturePACLifetime.ValueInt64()),
			PosturePACLifetimeUnits:           details.PosturePACLifetimeUnits.ValueString(),
			AllowAnonymousProvisioning:        client.FlexBool(details.AllowAnonymousProvisioning.ValueBool()),
			AuthProvisioningRequireClientCert: client.FlexBool(details.AuthProvisioningRequireClientCert.ValueBool()),
			ClientCertificateAuth:             client.FlexBool(details.ClientCertificateAuth.ValueBool()),
			AllowAuthenticatedProvisioning:    client.FlexBool(details.AllowAuthenticatedProvisioning.ValueBool()),
			CertificateComparison:             details.CertificateComparison.ValueString(),
			SessionTimeout:                    client.FlexInt(details.SessionTimeout.ValueInt64()),
			SessionCacheEnable:                client.FlexBool(details.SessionCacheEnable.ValueBool()),
			Challenge:                         details.Challenge.ValueString(),
			AllowFastReconnect:                client.FlexBool(details.AllowFastReconnect.ValueBool()),
			NAPSupportEnable:                  client.FlexBool(details.NAPSupportEnable.ValueBool()),
			EnforceCryptoBinding:              details.EnforceCryptoBinding.ValueString(),
			PublicPassword:                    details.PublicPassword.ValueString(),
			PublicUsername:                    details.PublicUsername.ValueString(),
			GroupName:                         details.GroupName.ValueString(),
			ServerID:                          details.ServerID.ValueString(),
			AutzRequired:                      client.FlexBool(details.AutzRequired.ValueBool()),
			OCSPEnable:                        details.OCSPEnable.ValueString(),
			OCSPURL:                           details.OCSPURL.ValueString(),
			OverrideCertURL:                   client.FlexBool(details.OverrideCertURL.ValueBool()),
			EncryptionScheme:                  details.EncryptionScheme.ValueString(),
			AllowUnknownClients:               client.FlexBool(details.AllowUnknownClients.ValueBool()),
			PassResetFlow:                     details.PassResetFlow.ValueString(),
			NoOfRetries:                       client.FlexInt(details.NoOfRetries.ValueInt64()),
		}
	}

	// Call API
	result, err := r.client.CreateAuthMethod(ctx, authMethodCreate)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create auth method, got error: %s", err))
		return
	}

	// Update state with result
	data.ID = types.StringValue(strconv.Itoa(result.ID))
	data.Name = types.StringValue(result.Name)
	data.Description = types.StringValue(result.Description)
	data.MethodType = types.StringValue(result.MethodType)

	if len(result.InnerMethods) > 0 {
		innerMethods, _ := types.ListValueFrom(ctx, types.StringType, result.InnerMethods)
		data.InnerMethods = innerMethods
	} else {
		data.InnerMethods = types.ListNull(types.StringType)
	}

	if result.Details != nil {
		var planDetails AuthMethodDetailsModel
		if len(data.Details) > 0 {
			planDetails = data.Details[0]
		}

		tflog.Debug(ctx, "DEBUG: AutzRequired Plan Value", map[string]interface{}{"value": planDetails.AutzRequired.ValueBool()})
		tflog.Debug(ctx, "DEBUG: AutzRequired API Value", map[string]interface{}{"value": bool(result.Details.AutzRequired)})

		details := AuthMethodDetailsModel{
			TunnelPACLifetime:                 getValueInt64(planDetails.TunnelPACLifetime, int64(result.Details.TunnelPACLifetime)),
			TunnelPACLifetimeUnits:            getValueString(planDetails.TunnelPACLifetimeUnits, result.Details.TunnelPACLifetimeUnits),
			UserAuthPACEnable:                 getValueBool(planDetails.UserAuthPACEnable, bool(result.Details.UserAuthPACEnable)),
			UserAuthPACLifetime:               getValueInt64(planDetails.UserAuthPACLifetime, int64(result.Details.UserAuthPACLifetime)),
			UserAuthPACLifetimeUnits:          getValueString(planDetails.UserAuthPACLifetimeUnits, result.Details.UserAuthPACLifetimeUnits),
			MachinePACEnable:                  getValueBool(planDetails.MachinePACEnable, bool(result.Details.MachinePACEnable)),
			MachinePACLifetime:                getValueInt64(planDetails.MachinePACLifetime, int64(result.Details.MachinePACLifetime)),
			MachinePACLifetimeUnits:           getValueString(planDetails.MachinePACLifetimeUnits, result.Details.MachinePACLifetimeUnits),
			PosturePACEnable:                  getValueBool(planDetails.PosturePACEnable, bool(result.Details.PosturePACEnable)),
			PosturePACLifetime:                getValueInt64(planDetails.PosturePACLifetime, int64(result.Details.PosturePACLifetime)),
			PosturePACLifetimeUnits:           getValueString(planDetails.PosturePACLifetimeUnits, result.Details.PosturePACLifetimeUnits),
			AllowAnonymousProvisioning:        getValueBool(planDetails.AllowAnonymousProvisioning, bool(result.Details.AllowAnonymousProvisioning)),
			AuthProvisioningRequireClientCert: getValueBool(planDetails.AuthProvisioningRequireClientCert, bool(result.Details.AuthProvisioningRequireClientCert)),
			ClientCertificateAuth:             getValueBool(planDetails.ClientCertificateAuth, bool(result.Details.ClientCertificateAuth)),
			AllowAuthenticatedProvisioning:    getValueBool(planDetails.AllowAuthenticatedProvisioning, bool(result.Details.AllowAuthenticatedProvisioning)),
			CertificateComparison:             getValueString(planDetails.CertificateComparison, result.Details.CertificateComparison),
			SessionTimeout:                    getValueInt64(planDetails.SessionTimeout, int64(result.Details.SessionTimeout)),
			SessionCacheEnable:                getValueBool(planDetails.SessionCacheEnable, bool(result.Details.SessionCacheEnable)),
			Challenge:                         getValueString(planDetails.Challenge, result.Details.Challenge),
			AllowFastReconnect:                getValueBool(planDetails.AllowFastReconnect, bool(result.Details.AllowFastReconnect)),
			NAPSupportEnable:                  getValueBool(planDetails.NAPSupportEnable, bool(result.Details.NAPSupportEnable)),
			EnforceCryptoBinding:              getValueString(planDetails.EnforceCryptoBinding, result.Details.EnforceCryptoBinding),
			PublicPassword:                    getValueString(planDetails.PublicPassword, result.Details.PublicPassword),
			PublicUsername:                    getValueString(planDetails.PublicUsername, result.Details.PublicUsername),
			GroupName:                         getValueString(planDetails.GroupName, result.Details.GroupName),
			ServerID:                          getValueString(planDetails.ServerID, result.Details.ServerID),
			AutzRequired:                      getValueBool(planDetails.AutzRequired, bool(result.Details.AutzRequired)),
			OCSPEnable:                        getValueString(planDetails.OCSPEnable, result.Details.OCSPEnable),
			OCSPURL:                           getValueString(planDetails.OCSPURL, result.Details.OCSPURL),
			OverrideCertURL:                   getValueBool(planDetails.OverrideCertURL, bool(result.Details.OverrideCertURL)),
			EncryptionScheme:                  getValueString(planDetails.EncryptionScheme, result.Details.EncryptionScheme),
			AllowUnknownClients:               getValueBool(planDetails.AllowUnknownClients, bool(result.Details.AllowUnknownClients)),
			PassResetFlow:                     getValueString(planDetails.PassResetFlow, result.Details.PassResetFlow),
			NoOfRetries:                       getValueInt64(planDetails.NoOfRetries, int64(result.Details.NoOfRetries)),
		}

		data.Details = []AuthMethodDetailsModel{details}
	} else {
		data.Details = nil
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AuthMethodResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AuthMethodResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, _ := strconv.Atoi(data.ID.ValueString())

	// Call API
	result, err := r.client.GetAuthMethod(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read auth method, got error: %s", err))
		return
	}

	if result == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	// Update state with result
	data.Name = types.StringValue(result.Name)
	data.Description = types.StringValue(result.Description)
	data.MethodType = types.StringValue(result.MethodType)

	if len(result.InnerMethods) > 0 {
		innerMethods, _ := types.ListValueFrom(ctx, types.StringType, result.InnerMethods)
		data.InnerMethods = innerMethods
	} else {
		data.InnerMethods = types.ListNull(types.StringType)
	}

	if result.Details != nil {
		details := AuthMethodDetailsModel{
			TunnelPACLifetime:                 types.Int64Value(int64(result.Details.TunnelPACLifetime)),
			TunnelPACLifetimeUnits:            types.StringValue(result.Details.TunnelPACLifetimeUnits),
			UserAuthPACEnable:                 types.BoolValue(bool(result.Details.UserAuthPACEnable)),
			UserAuthPACLifetime:               types.Int64Value(int64(result.Details.UserAuthPACLifetime)),
			UserAuthPACLifetimeUnits:          types.StringValue(result.Details.UserAuthPACLifetimeUnits),
			MachinePACEnable:                  types.BoolValue(bool(result.Details.MachinePACEnable)),
			MachinePACLifetime:                types.Int64Value(int64(result.Details.MachinePACLifetime)),
			MachinePACLifetimeUnits:           types.StringValue(result.Details.MachinePACLifetimeUnits),
			PosturePACEnable:                  types.BoolValue(bool(result.Details.PosturePACEnable)),
			PosturePACLifetime:                types.Int64Value(int64(result.Details.PosturePACLifetime)),
			PosturePACLifetimeUnits:           types.StringValue(result.Details.PosturePACLifetimeUnits),
			AllowAnonymousProvisioning:        types.BoolValue(bool(result.Details.AllowAnonymousProvisioning)),
			AuthProvisioningRequireClientCert: types.BoolValue(bool(result.Details.AuthProvisioningRequireClientCert)),
			ClientCertificateAuth:             types.BoolValue(bool(result.Details.ClientCertificateAuth)),
			AllowAuthenticatedProvisioning:    types.BoolValue(bool(result.Details.AllowAuthenticatedProvisioning)),
			CertificateComparison:             types.StringValue(result.Details.CertificateComparison),
			SessionTimeout:                    types.Int64Value(int64(result.Details.SessionTimeout)),
			SessionCacheEnable:                types.BoolValue(bool(result.Details.SessionCacheEnable)),
			Challenge:                         types.StringValue(result.Details.Challenge),
			AllowFastReconnect:                types.BoolValue(bool(result.Details.AllowFastReconnect)),
			NAPSupportEnable:                  types.BoolValue(bool(result.Details.NAPSupportEnable)),
			EnforceCryptoBinding:              types.StringValue(result.Details.EnforceCryptoBinding),
			PublicPassword:                    types.StringValue(result.Details.PublicPassword),
			PublicUsername:                    types.StringValue(result.Details.PublicUsername),
			GroupName:                         types.StringValue(result.Details.GroupName),
			ServerID:                          types.StringValue(result.Details.ServerID),
			AutzRequired:                      types.BoolValue(bool(result.Details.AutzRequired)),
			OCSPEnable:                        types.StringValue(result.Details.OCSPEnable),
			OCSPURL:                           types.StringValue(result.Details.OCSPURL),
			OverrideCertURL:                   types.BoolValue(bool(result.Details.OverrideCertURL)),
			EncryptionScheme:                  types.StringValue(result.Details.EncryptionScheme),
			AllowUnknownClients:               types.BoolValue(bool(result.Details.AllowUnknownClients)),
			PassResetFlow:                     types.StringValue(result.Details.PassResetFlow),
			NoOfRetries:                       types.Int64Value(int64(result.Details.NoOfRetries)),
		}
		data.Details = []AuthMethodDetailsModel{details}
	} else {
		data.Details = nil
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AuthMethodResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data AuthMethodResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var planDetails AuthMethodDetailsModel
	if len(data.Details) > 0 {
		planDetails = data.Details[0]
	}

	id, _ := strconv.Atoi(data.ID.ValueString())

	// Convert model to API client struct
	authMethodUpdate := &client.AuthMethodUpdate{
		Name:        data.Name.ValueString(),
		Description: data.Description.ValueString(),
		MethodType:  data.MethodType.ValueString(),
	}

	if !data.InnerMethods.IsNull() && !data.InnerMethods.IsUnknown() {
		var innerMethods []string
		data.InnerMethods.ElementsAs(ctx, &innerMethods, false)
		authMethodUpdate.InnerMethods = innerMethods
	}

	if len(data.Details) > 0 {
		details := data.Details[0]
		authMethodUpdate.Details = &client.AuthMethodDetails{
			TunnelPACLifetime:                 client.FlexInt(details.TunnelPACLifetime.ValueInt64()),
			TunnelPACLifetimeUnits:            details.TunnelPACLifetimeUnits.ValueString(),
			UserAuthPACEnable:                 client.FlexBool(details.UserAuthPACEnable.ValueBool()),
			UserAuthPACLifetime:               client.FlexInt(details.UserAuthPACLifetime.ValueInt64()),
			UserAuthPACLifetimeUnits:          details.UserAuthPACLifetimeUnits.ValueString(),
			MachinePACEnable:                  client.FlexBool(details.MachinePACEnable.ValueBool()),
			MachinePACLifetime:                client.FlexInt(details.MachinePACLifetime.ValueInt64()),
			MachinePACLifetimeUnits:           details.MachinePACLifetimeUnits.ValueString(),
			PosturePACEnable:                  client.FlexBool(details.PosturePACEnable.ValueBool()),
			PosturePACLifetime:                client.FlexInt(details.PosturePACLifetime.ValueInt64()),
			PosturePACLifetimeUnits:           details.PosturePACLifetimeUnits.ValueString(),
			AllowAnonymousProvisioning:        client.FlexBool(details.AllowAnonymousProvisioning.ValueBool()),
			AuthProvisioningRequireClientCert: client.FlexBool(details.AuthProvisioningRequireClientCert.ValueBool()),
			ClientCertificateAuth:             client.FlexBool(details.ClientCertificateAuth.ValueBool()),
			AllowAuthenticatedProvisioning:    client.FlexBool(details.AllowAuthenticatedProvisioning.ValueBool()),
			CertificateComparison:             details.CertificateComparison.ValueString(),
			SessionTimeout:                    client.FlexInt(details.SessionTimeout.ValueInt64()),
			SessionCacheEnable:                client.FlexBool(details.SessionCacheEnable.ValueBool()),
			Challenge:                         details.Challenge.ValueString(),
			AllowFastReconnect:                client.FlexBool(details.AllowFastReconnect.ValueBool()),
			NAPSupportEnable:                  client.FlexBool(details.NAPSupportEnable.ValueBool()),
			EnforceCryptoBinding:              details.EnforceCryptoBinding.ValueString(),
			PublicPassword:                    details.PublicPassword.ValueString(),
			PublicUsername:                    details.PublicUsername.ValueString(),
			GroupName:                         details.GroupName.ValueString(),
			ServerID:                          details.ServerID.ValueString(),
			AutzRequired:                      client.FlexBool(details.AutzRequired.ValueBool()),
			OCSPEnable:                        details.OCSPEnable.ValueString(),
			OCSPURL:                           details.OCSPURL.ValueString(),
			OverrideCertURL:                   client.FlexBool(details.OverrideCertURL.ValueBool()),
			EncryptionScheme:                  details.EncryptionScheme.ValueString(),
			AllowUnknownClients:               client.FlexBool(details.AllowUnknownClients.ValueBool()),
			PassResetFlow:                     details.PassResetFlow.ValueString(),
			NoOfRetries:                       client.FlexInt(details.NoOfRetries.ValueInt64()),
		}
	}

	// Call API
	result, err := r.client.UpdateAuthMethod(ctx, id, authMethodUpdate)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating Auth Method",
			"Could not update Auth Method, unexpected error: "+err.Error(),
		)
		return
	}

	// Update state with refreshed data
	data.Name = types.StringValue(result.Name)
	data.Description = types.StringValue(result.Description)
	data.MethodType = types.StringValue(result.MethodType)

	if len(result.InnerMethods) > 0 {
		innerMethods, _ := types.ListValueFrom(ctx, types.StringType, result.InnerMethods)
		data.InnerMethods = innerMethods
	} else {
		data.InnerMethods = types.ListNull(types.StringType)
	}

	if result.Details != nil {
		details := AuthMethodDetailsModel{
			TunnelPACLifetime:                 getValueInt64(planDetails.TunnelPACLifetime, int64(result.Details.TunnelPACLifetime)),
			TunnelPACLifetimeUnits:            getValueString(planDetails.TunnelPACLifetimeUnits, result.Details.TunnelPACLifetimeUnits),
			UserAuthPACEnable:                 getValueBool(planDetails.UserAuthPACEnable, bool(result.Details.UserAuthPACEnable)),
			UserAuthPACLifetime:               getValueInt64(planDetails.UserAuthPACLifetime, int64(result.Details.UserAuthPACLifetime)),
			UserAuthPACLifetimeUnits:          getValueString(planDetails.UserAuthPACLifetimeUnits, result.Details.UserAuthPACLifetimeUnits),
			MachinePACEnable:                  getValueBool(planDetails.MachinePACEnable, bool(result.Details.MachinePACEnable)),
			MachinePACLifetime:                getValueInt64(planDetails.MachinePACLifetime, int64(result.Details.MachinePACLifetime)),
			MachinePACLifetimeUnits:           getValueString(planDetails.MachinePACLifetimeUnits, result.Details.MachinePACLifetimeUnits),
			PosturePACEnable:                  getValueBool(planDetails.PosturePACEnable, bool(result.Details.PosturePACEnable)),
			PosturePACLifetime:                getValueInt64(planDetails.PosturePACLifetime, int64(result.Details.PosturePACLifetime)),
			PosturePACLifetimeUnits:           getValueString(planDetails.PosturePACLifetimeUnits, result.Details.PosturePACLifetimeUnits),
			AllowAnonymousProvisioning:        getValueBool(planDetails.AllowAnonymousProvisioning, bool(result.Details.AllowAnonymousProvisioning)),
			AuthProvisioningRequireClientCert: getValueBool(planDetails.AuthProvisioningRequireClientCert, bool(result.Details.AuthProvisioningRequireClientCert)),
			ClientCertificateAuth:             getValueBool(planDetails.ClientCertificateAuth, bool(result.Details.ClientCertificateAuth)),
			AllowAuthenticatedProvisioning:    getValueBool(planDetails.AllowAuthenticatedProvisioning, bool(result.Details.AllowAuthenticatedProvisioning)),
			CertificateComparison:             getValueString(planDetails.CertificateComparison, result.Details.CertificateComparison),
			SessionTimeout:                    getValueInt64(planDetails.SessionTimeout, int64(result.Details.SessionTimeout)),
			SessionCacheEnable:                getValueBool(planDetails.SessionCacheEnable, bool(result.Details.SessionCacheEnable)),
			Challenge:                         getValueString(planDetails.Challenge, result.Details.Challenge),
			AllowFastReconnect:                getValueBool(planDetails.AllowFastReconnect, bool(result.Details.AllowFastReconnect)),
			NAPSupportEnable:                  getValueBool(planDetails.NAPSupportEnable, bool(result.Details.NAPSupportEnable)),
			EnforceCryptoBinding:              getValueString(planDetails.EnforceCryptoBinding, result.Details.EnforceCryptoBinding),
			PublicPassword:                    getValueString(planDetails.PublicPassword, result.Details.PublicPassword),
			PublicUsername:                    getValueString(planDetails.PublicUsername, result.Details.PublicUsername),
			GroupName:                         getValueString(planDetails.GroupName, result.Details.GroupName),
			ServerID:                          getValueString(planDetails.ServerID, result.Details.ServerID),
			AutzRequired:                      getValueBool(planDetails.AutzRequired, bool(result.Details.AutzRequired)),
			OCSPEnable:                        getValueString(planDetails.OCSPEnable, result.Details.OCSPEnable),
			OCSPURL:                           getValueString(planDetails.OCSPURL, result.Details.OCSPURL),
			OverrideCertURL:                   getValueBool(planDetails.OverrideCertURL, bool(result.Details.OverrideCertURL)),
			EncryptionScheme:                  getValueString(planDetails.EncryptionScheme, result.Details.EncryptionScheme),
			AllowUnknownClients:               getValueBool(planDetails.AllowUnknownClients, bool(result.Details.AllowUnknownClients)),
			PassResetFlow:                     getValueString(planDetails.PassResetFlow, result.Details.PassResetFlow),
			NoOfRetries:                       getValueInt64(planDetails.NoOfRetries, int64(result.Details.NoOfRetries)),
		}
		data.Details = []AuthMethodDetailsModel{details}
	} else {
		data.Details = nil
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AuthMethodResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip if the plan is being destroyed
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan, state AuthMethodResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// If details block exists in both plan and state
	if len(plan.Details) > 0 && len(state.Details) > 0 {
		planDetails := plan.Details[0]
		stateDetails := state.Details[0]

		// Helper to copy state to plan if plan is unknown and state is known
		copyIfUnknown := func(planVal, stateVal interface{}) interface{} {
			switch p := planVal.(type) {
			case types.String:
				if p.IsUnknown() && !stateVal.(types.String).IsNull() && !stateVal.(types.String).IsUnknown() {
					return stateVal
				}
			case types.Bool:
				if p.IsUnknown() && !stateVal.(types.Bool).IsNull() && !stateVal.(types.Bool).IsUnknown() {
					return stateVal
				}
			case types.Int64:
				if p.IsUnknown() && !stateVal.(types.Int64).IsNull() && !stateVal.(types.Int64).IsUnknown() {
					return stateVal
				}
			}
			return planVal
		}

		planDetails.TunnelPACLifetime = copyIfUnknown(planDetails.TunnelPACLifetime, stateDetails.TunnelPACLifetime).(types.Int64)
		planDetails.TunnelPACLifetimeUnits = copyIfUnknown(planDetails.TunnelPACLifetimeUnits, stateDetails.TunnelPACLifetimeUnits).(types.String)
		planDetails.UserAuthPACEnable = copyIfUnknown(planDetails.UserAuthPACEnable, stateDetails.UserAuthPACEnable).(types.Bool)
		planDetails.UserAuthPACLifetime = copyIfUnknown(planDetails.UserAuthPACLifetime, stateDetails.UserAuthPACLifetime).(types.Int64)
		planDetails.UserAuthPACLifetimeUnits = copyIfUnknown(planDetails.UserAuthPACLifetimeUnits, stateDetails.UserAuthPACLifetimeUnits).(types.String)
		planDetails.MachinePACEnable = copyIfUnknown(planDetails.MachinePACEnable, stateDetails.MachinePACEnable).(types.Bool)
		planDetails.MachinePACLifetime = copyIfUnknown(planDetails.MachinePACLifetime, stateDetails.MachinePACLifetime).(types.Int64)
		planDetails.MachinePACLifetimeUnits = copyIfUnknown(planDetails.MachinePACLifetimeUnits, stateDetails.MachinePACLifetimeUnits).(types.String)
		planDetails.PosturePACEnable = copyIfUnknown(planDetails.PosturePACEnable, stateDetails.PosturePACEnable).(types.Bool)
		planDetails.PosturePACLifetime = copyIfUnknown(planDetails.PosturePACLifetime, stateDetails.PosturePACLifetime).(types.Int64)
		planDetails.PosturePACLifetimeUnits = copyIfUnknown(planDetails.PosturePACLifetimeUnits, stateDetails.PosturePACLifetimeUnits).(types.String)
		planDetails.AllowAnonymousProvisioning = copyIfUnknown(planDetails.AllowAnonymousProvisioning, stateDetails.AllowAnonymousProvisioning).(types.Bool)
		planDetails.AuthProvisioningRequireClientCert = copyIfUnknown(planDetails.AuthProvisioningRequireClientCert, stateDetails.AuthProvisioningRequireClientCert).(types.Bool)
		planDetails.ClientCertificateAuth = copyIfUnknown(planDetails.ClientCertificateAuth, stateDetails.ClientCertificateAuth).(types.Bool)
		planDetails.AllowAuthenticatedProvisioning = copyIfUnknown(planDetails.AllowAuthenticatedProvisioning, stateDetails.AllowAuthenticatedProvisioning).(types.Bool)
		planDetails.CertificateComparison = copyIfUnknown(planDetails.CertificateComparison, stateDetails.CertificateComparison).(types.String)
		planDetails.SessionTimeout = copyIfUnknown(planDetails.SessionTimeout, stateDetails.SessionTimeout).(types.Int64)
		planDetails.SessionCacheEnable = copyIfUnknown(planDetails.SessionCacheEnable, stateDetails.SessionCacheEnable).(types.Bool)
		planDetails.Challenge = copyIfUnknown(planDetails.Challenge, stateDetails.Challenge).(types.String)
		planDetails.AllowFastReconnect = copyIfUnknown(planDetails.AllowFastReconnect, stateDetails.AllowFastReconnect).(types.Bool)
		planDetails.NAPSupportEnable = copyIfUnknown(planDetails.NAPSupportEnable, stateDetails.NAPSupportEnable).(types.Bool)
		planDetails.EnforceCryptoBinding = copyIfUnknown(planDetails.EnforceCryptoBinding, stateDetails.EnforceCryptoBinding).(types.String)
		planDetails.PublicPassword = copyIfUnknown(planDetails.PublicPassword, stateDetails.PublicPassword).(types.String)
		planDetails.PublicUsername = copyIfUnknown(planDetails.PublicUsername, stateDetails.PublicUsername).(types.String)
		planDetails.GroupName = copyIfUnknown(planDetails.GroupName, stateDetails.GroupName).(types.String)
		planDetails.ServerID = copyIfUnknown(planDetails.ServerID, stateDetails.ServerID).(types.String)
		planDetails.AutzRequired = copyIfUnknown(planDetails.AutzRequired, stateDetails.AutzRequired).(types.Bool)
		planDetails.OCSPEnable = copyIfUnknown(planDetails.OCSPEnable, stateDetails.OCSPEnable).(types.String)
		planDetails.OCSPURL = copyIfUnknown(planDetails.OCSPURL, stateDetails.OCSPURL).(types.String)
		planDetails.OverrideCertURL = copyIfUnknown(planDetails.OverrideCertURL, stateDetails.OverrideCertURL).(types.Bool)
		planDetails.EncryptionScheme = copyIfUnknown(planDetails.EncryptionScheme, stateDetails.EncryptionScheme).(types.String)
		planDetails.AllowUnknownClients = copyIfUnknown(planDetails.AllowUnknownClients, stateDetails.AllowUnknownClients).(types.Bool)
		planDetails.PassResetFlow = copyIfUnknown(planDetails.PassResetFlow, stateDetails.PassResetFlow).(types.String)
		planDetails.NoOfRetries = copyIfUnknown(planDetails.NoOfRetries, stateDetails.NoOfRetries).(types.Int64)

		plan.Details = []AuthMethodDetailsModel{planDetails}
	}

	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

func getValueString(plan types.String, apiVal string) types.String {
	if !plan.IsNull() && !plan.IsUnknown() {
		return plan
	}
	return types.StringValue(apiVal)
}

func getValueBool(plan types.Bool, apiVal bool) types.Bool {
	if !plan.IsNull() && !plan.IsUnknown() {
		return plan
	}
	return types.BoolValue(apiVal)
}

func getValueInt64(plan types.Int64, apiVal int64) types.Int64 {
	if !plan.IsNull() && !plan.IsUnknown() {
		return plan
	}
	return types.Int64Value(apiVal)
}

func (r *AuthMethodResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AuthMethodResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, _ := strconv.Atoi(data.ID.ValueString())

	// Call API
	err := r.client.DeleteAuthMethod(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete auth method, got error: %s", err))
		return
	}
}

func (r *AuthMethodResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
