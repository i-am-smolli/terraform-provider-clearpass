package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-clearpass/internal/client"
)

var (
	_ datasource.DataSource              = &certTrustListDataSource{}
	_ datasource.DataSourceWithConfigure = &certTrustListDataSource{}
)

func NewCertTrustListDataSource() datasource.DataSource {
	return &certTrustListDataSource{}
}

type certTrustListDataSource struct {
	client client.ClientInterface
}

func (d *certTrustListDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cert_trust_list"
}

func (d *certTrustListDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Data source for retrieving a single Certificate Trust List.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "ID of the certificate trust list.",
				Required:    true,
			},
			"cert_file": schema.StringAttribute{
				Description: "Certificate trust list file name.",
				Computed:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the certificate trust list is enabled.",
				Computed:    true,
			},
			"cert_usage": schema.ListAttribute{
				Description: "Usage of the certificate (e.g., Radius, WebUI).",
				ElementType: types.StringType,
				Computed:    true,
			},
		},
	}
}

func (d *certTrustListDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = req.ProviderData.(client.ClientInterface)
}

func (d *certTrustListDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state struct {
		ID        types.Int64  `tfsdk:"id"`
		CertFile  types.String `tfsdk:"cert_file"`
		Enabled   types.Bool   `tfsdk:"enabled"`
		CertUsage types.List   `tfsdk:"cert_usage"`
	}

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	certTrustList, err := d.client.GetCertTrustList(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Certificate Trust List",
			"Could not read Certificate Trust List ID "+fmt.Sprintf("%d", state.ID.ValueInt64())+": "+err.Error(),
		)
		return
	}

	// Not found
	if certTrustList == nil {
		resp.Diagnostics.AddError(
			"Certificate Trust List Not Found",
			"Certificate Trust List ID "+fmt.Sprintf("%d", state.ID.ValueInt64())+" was not found in ClearPass.",
		)
		return
	}

	state.ID = types.Int64Value(int64(certTrustList.ID))
	state.CertFile = types.StringValue(certTrustList.CertFile)
	state.Enabled = types.BoolValue(certTrustList.Enabled)

	var usages []types.String
	for _, u := range certTrustList.CertUsage {
		usages = append(usages, types.StringValue(u))
	}
	usagesList, diags := types.ListValueFrom(ctx, types.StringType, usages)
	resp.Diagnostics.Append(diags...)

	state.CertUsage = usagesList

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
