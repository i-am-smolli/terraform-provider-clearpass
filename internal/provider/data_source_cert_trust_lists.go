package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-clearpass/internal/client"
)

var (
	_ datasource.DataSource              = &certTrustListsDataSource{}
	_ datasource.DataSourceWithConfigure = &certTrustListsDataSource{}
)

func NewCertTrustListsDataSource() datasource.DataSource {
	return &certTrustListsDataSource{}
}

type certTrustListsDataSource struct {
	client client.ClientInterface
}

func (d *certTrustListsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cert_trust_lists"
}

func (d *certTrustListsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves all Certificate Trust List entries configured in ClearPass. " +
			"Certificate Trust Lists define which CA certificates are trusted for EAP-TLS and other certificate-based authentication.",
		Attributes: map[string]schema.Attribute{
			"lists": schema.ListNestedAttribute{
				MarkdownDescription: "List of Certificate Trust List entries.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							MarkdownDescription: "Numeric ID of the certificate trust list entry.",
							Computed:            true,
						},
						"cert_file": schema.StringAttribute{
							MarkdownDescription: "The file name of the trusted CA certificate.",
							Computed:            true,
						},
						"enabled": schema.BoolAttribute{
							MarkdownDescription: "Whether this certificate trust list entry is enabled for use.",
							Computed:            true,
						},
						"cert_usage": schema.ListAttribute{
							MarkdownDescription: "The services this CA certificate is trusted for (e.g., `EAP`, `RadSec`, `Database`, `Web`).",
							ElementType:         types.StringType,
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

func (d *certTrustListsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = req.ProviderData.(client.ClientInterface)
}

func (d *certTrustListsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state struct {
		Lists []struct {
			ID        types.Int64  `tfsdk:"id"`
			CertFile  types.String `tfsdk:"cert_file"`
			Enabled   types.Bool   `tfsdk:"enabled"`
			CertUsage types.List   `tfsdk:"cert_usage"`
		} `tfsdk:"lists"`
	}

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := d.client.GetCertTrustLists(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Certificate Trust Lists",
			"Could not read Certificate Trust Lists: "+err.Error(),
		)
		return
	}

	for _, list := range result.Embedded.Items {
		var usages []types.String
		for _, u := range list.CertUsage {
			usages = append(usages, types.StringValue(u))
		}
		usagesList, diags := types.ListValueFrom(ctx, types.StringType, usages)
		resp.Diagnostics.Append(diags...)

		state.Lists = append(state.Lists, struct {
			ID        types.Int64  `tfsdk:"id"`
			CertFile  types.String `tfsdk:"cert_file"`
			Enabled   types.Bool   `tfsdk:"enabled"`
			CertUsage types.List   `tfsdk:"cert_usage"`
		}{
			ID:        types.Int64Value(int64(list.ID)),
			CertFile:  types.StringValue(list.CertFile),
			Enabled:   types.BoolValue(list.Enabled),
			CertUsage: usagesList,
		})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
