package provider

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &AuthMethodDataSource{}

func NewAuthMethodDataSource() datasource.DataSource {
	return &AuthMethodDataSource{}
}

// AuthMethodDataSource defines the data source implementation.
type AuthMethodDataSource struct {
	client client.ClientInterface
}

// AuthMethodDataSourceModel describes the data source data model.
type AuthMethodDataSourceModel struct {
	ID           types.String             `tfsdk:"id"`
	Name         types.String             `tfsdk:"name"`
	Description  types.String             `tfsdk:"description"`
	MethodType   types.String             `tfsdk:"method_type"`
	InnerMethods types.List               `tfsdk:"inner_methods"`
	Details      []AuthMethodDetailsModel `tfsdk:"details"`
}

func (d *AuthMethodDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_auth_method"
}

func (d *AuthMethodDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves the details of a specific authentication method in ClearPass by its ID.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The numeric ID of the authentication method to retrieve.",
			},
			"name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Name of the auth method",
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Description of the authentication method.",
			},
			"method_type": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Type of the authentication method.",
			},
			"inner_methods": schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				MarkdownDescription: "List of inner methods for the authentication method.",
			},
		},
		Blocks: map[string]schema.Block{
			"details": schema.ListNestedBlock{
				MarkdownDescription: "Configuration details specific to the authentication method type.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"tunnel_pac_lifetime": schema.Int64Attribute{
							Computed:            true,
							MarkdownDescription: "Tunnel PAC Expire Time",
						},
						"tunnel_pac_lifetime_units": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Tunnel PAC Expire Time Units",
						},
						"user_auth_pac_enable": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Authorization PAC",
						},
						"user_auth_pac_lifetime": schema.Int64Attribute{
							Computed:            true,
							MarkdownDescription: "Authorization PAC Expire Time",
						},
						"user_auth_pac_lifetime_units": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Authorization PAC Expire Time Units",
						},
						"machine_pac_enable": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Machine PAC",
						},
						"machine_pac_lifetime": schema.Int64Attribute{
							Computed:            true,
							MarkdownDescription: "Machine PAC Expire Time",
						},
						"machine_pac_lifetime_units": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Machine PAC Expire Time Units",
						},
						"posture_pac_enable": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Posture PAC",
						},
						"posture_pac_lifetime": schema.Int64Attribute{
							Computed:            true,
							MarkdownDescription: "Posture PAC Expire Time",
						},
						"posture_pac_lifetime_units": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Posture PAC Expire Time Units",
						},
						"allow_anonymous_provisioning": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Allow anonymous mode (requires no server certificate)",
						},
						"auth_provisioning_require_client_cert": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Require end-host certificate for provisioning",
						},
						"client_certificate_auth": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "End-Host Authentication",
						},
						"allow_authenticated_provisioning": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Allow authenticated mode (requires server certificate)",
						},
						"certificate_comparison": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Certificate Comparison. One of: none, dn, cn, san, cn_or_san, binary",
						},
						"session_timeout": schema.Int64Attribute{
							Computed:            true,
							MarkdownDescription: "Session Timeout",
						},
						"session_cache_enable": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Session Resumption",
						},
						"challenge": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Challenge",
						},
						"allow_fast_reconnect": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Fast Reconnect",
						},
						"nap_support_enable": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Microsoft NAP Support",
						},
						"enforce_crypto_binding": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Cryptobinding. One of: none, optional, required",
						},
						"public_password": schema.StringAttribute{
							Computed:            true,
							Sensitive:           true,
							MarkdownDescription: "Public Password",
						},
						"public_username": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Public Username",
						},
						"group_name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Group",
						},
						"server_id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Server Id",
						},
						"autz_required": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Authorization Required.",
						},
						"ocsp_enable": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Verify Certificate using OCSP. One of: none, optional, required",
						},
						"ocsp_url": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "OCSP URL",
						},
						"override_cert_url": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Override OCSP URL from Client",
						},
						"encryption_scheme": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Enable Aruba-SSO",
						},
						"allow_unknown_clients": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Allow Unknown End-Hosts",
						},
						"pass_reset_flow": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Password reset sends in",
						},
						"no_of_retries": schema.Int64Attribute{
							Computed:            true,
							MarkdownDescription: "Number of retries",
						},
					},
				},
			},
		},
	}
}

func (d *AuthMethodDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
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

func (d *AuthMethodDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data AuthMethodDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Invalid ID: %s", err))
		return
	}

	// Call API
	result, err := d.client.GetAuthMethod(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read auth method, got error: %s", err))
		return
	}

	if result == nil {
		resp.Diagnostics.AddError("Error", "Auth Method not found")
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

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
