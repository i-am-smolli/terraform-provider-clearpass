package provider

import (
	"context"
	"os"

	// Import our SDK (Box 3).
	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure clearpassProvider implements provider.Provider.
var _ provider.Provider = &clearpassProvider{}

// clearpassProvider defines the provider implementation.
type clearpassProvider struct {
	version string
}

// providerModel defines the provider configuration data model.
// This is what the user will type in the provider { ... } block.
type providerModel struct {
	Host         types.String `tfsdk:"host"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
	Insecure     types.Bool   `tfsdk:"insecure"`
}

// New is the factory function for the provider.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &clearpassProvider{
			version: version,
		}
	}
}

// Metadata returns the provider's metadata.
func (p *clearpassProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "clearpass"
	resp.Version = p.version
}

// Schema defines the provider's configuration HCL.
func (p *clearpassProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A Terraform provider for managing Aruba ClearPass Policy Manager.",
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Description: "ClearPass host (IP or FQDN).",
				Required:    true,
			},
			"client_id": schema.StringAttribute{
				Description: "The OAuth2 Client ID.",
				Required:    true,
			},
			"client_secret": schema.StringAttribute{
				Description: "The OAuth2 Client Secret.",
				Required:    true,
				Sensitive:   true, // Marks this as a sensitive field
			},
			"insecure": schema.BoolAttribute{
				Description: "Allow insecure HTTPS connections (self-signed certs).",
				Optional:    true,
			},
		},
	}
}

// Configure is where we read the user's config and create our API client.
// THIS IS THE BRIDGE BETWEEN PROVIDER (BOX 2) AND CLIENT (BOX 3).
func (p *clearpassProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel

	// Read configuration data from HCL
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read from environment variables if not set, as a fallback
	if config.Host.IsNull() {
		config.Host = types.StringValue(os.Getenv("CLEARPASS_HOST"))
	}
	// ... (add similar logic for CLEARPASS_CLIENT_ID, etc.)

	// Check for missing configuration
	if config.Host.IsNull() || config.ClientID.IsNull() || config.ClientSecret.IsNull() {
		resp.Diagnostics.AddError(
			"Missing Provider Configuration",
			"host, client_id, and client_secret must be provided.",
		)
		return
	}

	// === THIS IS THE MAGIC ===
	// 1. Get the values from the HCL config
	host := config.Host.ValueString()
	clientID := config.ClientID.ValueString()
	clientSecret := config.ClientSecret.ValueString()
	insecure := config.Insecure.ValueBool()

	// 2. Call our client's GetAccessToken function!
	authResp, err := client.GetAccessToken(ctx, host, clientID, clientSecret, insecure)
	if err != nil {
		resp.Diagnostics.AddError("Authentication Failed", err.Error())
		return
	}

	// 3. Create our API client with the new token
	apiClient := client.NewClient(host, authResp.AccessToken, insecure)

	// 4. Pass the configured client to all resources
	// The client is stored in the 'resp' object for resources to retrieve.
	resp.ResourceData = apiClient
	resp.DataSourceData = apiClient
}

// Resources defines the list of resources managed by the provider.
func (p *clearpassProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewLocalUserResource,
		NewRoleResource,
		NewRoleMappingResource,
		NewEnforcementProfileResource,
		NewEnforcementPolicyResource,
		NewServiceResource,
		NewServiceCertResource,
		NewCertTrustListResource,
		NewAuthMethodResource,
	}
}

// DataSources defines the list of data sources managed by the provider.
func (p *clearpassProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		// (We will add data sources later)
	}
}
