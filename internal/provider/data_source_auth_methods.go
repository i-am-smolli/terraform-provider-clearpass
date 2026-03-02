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

var _ datasource.DataSource = &AuthMethodsDataSource{}

func NewAuthMethodsDataSource() datasource.DataSource {
	return &AuthMethodsDataSource{}
}

type AuthMethodsDataSource struct {
	client client.ClientInterface
}

type AuthMethodsDataSourceModel struct {
	ID          types.String                `tfsdk:"id"`
	AuthMethods []AuthMethodDataSourceModel `tfsdk:"auth_methods"`
}

func (d *AuthMethodsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_auth_methods"
}

func (d *AuthMethodsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "List of Authentication Methods Data Source.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Placeholder identifier",
			},
		},
		Blocks: map[string]schema.Block{
			"auth_methods": schema.ListNestedBlock{
				MarkdownDescription: "List of authentication methods.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Numeric ID of the auth method",
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
										MarkdownDescription: "Allow anonymous mode",
									},
									"auth_provisioning_require_client_cert": schema.BoolAttribute{
										Computed:            true,
										MarkdownDescription: "Require end-host cert",
									},
									"client_certificate_auth": schema.BoolAttribute{
										Computed:            true,
										MarkdownDescription: "End-Host Authentication",
									},
									"allow_authenticated_provisioning": schema.BoolAttribute{
										Computed:            true,
										MarkdownDescription: "Allow authenticated mode",
									},
									"certificate_comparison": schema.StringAttribute{
										Computed:            true,
										MarkdownDescription: "Certificate Comparison",
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
										MarkdownDescription: "Cryptobinding",
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
										MarkdownDescription: "Verify Certificate using OCSP",
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
				},
			},
		},
	}
}

func (d *AuthMethodsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *AuthMethodsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data AuthMethodsDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := d.client.GetAuthMethods(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read auth methods, got error: %s", err))
		return
	}

	data.ID = types.StringValue("auth_methods")

	var authMethods []AuthMethodDataSourceModel
	for _, am := range result.Embedded.Items {
		item := AuthMethodDataSourceModel{
			ID:          types.StringValue(strconv.Itoa(am.ID)),
			Name:        types.StringValue(am.Name),
			Description: types.StringValue(am.Description),
			MethodType:  types.StringValue(am.MethodType),
		}

		if len(am.InnerMethods) > 0 {
			innerMethods, _ := types.ListValueFrom(ctx, types.StringType, am.InnerMethods)
			item.InnerMethods = innerMethods
		} else {
			item.InnerMethods = types.ListNull(types.StringType)
		}

		if am.Details != nil {
			details := AuthMethodDetailsModel{
				TunnelPACLifetime:                 types.Int64Value(int64(am.Details.TunnelPACLifetime)),
				TunnelPACLifetimeUnits:            types.StringValue(am.Details.TunnelPACLifetimeUnits),
				UserAuthPACEnable:                 types.BoolValue(bool(am.Details.UserAuthPACEnable)),
				UserAuthPACLifetime:               types.Int64Value(int64(am.Details.UserAuthPACLifetime)),
				UserAuthPACLifetimeUnits:          types.StringValue(am.Details.UserAuthPACLifetimeUnits),
				MachinePACEnable:                  types.BoolValue(bool(am.Details.MachinePACEnable)),
				MachinePACLifetime:                types.Int64Value(int64(am.Details.MachinePACLifetime)),
				MachinePACLifetimeUnits:           types.StringValue(am.Details.MachinePACLifetimeUnits),
				PosturePACEnable:                  types.BoolValue(bool(am.Details.PosturePACEnable)),
				PosturePACLifetime:                types.Int64Value(int64(am.Details.PosturePACLifetime)),
				PosturePACLifetimeUnits:           types.StringValue(am.Details.PosturePACLifetimeUnits),
				AllowAnonymousProvisioning:        types.BoolValue(bool(am.Details.AllowAnonymousProvisioning)),
				AuthProvisioningRequireClientCert: types.BoolValue(bool(am.Details.AuthProvisioningRequireClientCert)),
				ClientCertificateAuth:             types.BoolValue(bool(am.Details.ClientCertificateAuth)),
				AllowAuthenticatedProvisioning:    types.BoolValue(bool(am.Details.AllowAuthenticatedProvisioning)),
				CertificateComparison:             types.StringValue(am.Details.CertificateComparison),
				SessionTimeout:                    types.Int64Value(int64(am.Details.SessionTimeout)),
				SessionCacheEnable:                types.BoolValue(bool(am.Details.SessionCacheEnable)),
				Challenge:                         types.StringValue(am.Details.Challenge),
				AllowFastReconnect:                types.BoolValue(bool(am.Details.AllowFastReconnect)),
				NAPSupportEnable:                  types.BoolValue(bool(am.Details.NAPSupportEnable)),
				EnforceCryptoBinding:              types.StringValue(am.Details.EnforceCryptoBinding),
				PublicPassword:                    types.StringValue(am.Details.PublicPassword),
				PublicUsername:                    types.StringValue(am.Details.PublicUsername),
				GroupName:                         types.StringValue(am.Details.GroupName),
				ServerID:                          types.StringValue(am.Details.ServerID),
				AutzRequired:                      types.BoolValue(bool(am.Details.AutzRequired)),
				OCSPEnable:                        types.StringValue(am.Details.OCSPEnable),
				OCSPURL:                           types.StringValue(am.Details.OCSPURL),
				OverrideCertURL:                   types.BoolValue(bool(am.Details.OverrideCertURL)),
				EncryptionScheme:                  types.StringValue(am.Details.EncryptionScheme),
				AllowUnknownClients:               types.BoolValue(bool(am.Details.AllowUnknownClients)),
				PassResetFlow:                     types.StringValue(am.Details.PassResetFlow),
				NoOfRetries:                       types.Int64Value(int64(am.Details.NoOfRetries)),
			}
			item.Details = []AuthMethodDetailsModel{details}
		} else {
			item.Details = nil
		}
		authMethods = append(authMethods, item)
	}

	data.AuthMethods = authMethods

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
