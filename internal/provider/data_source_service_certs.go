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
	_ datasource.DataSource              = &serviceCertsDataSource{}
	_ datasource.DataSourceWithConfigure = &serviceCertsDataSource{}
)

func NewServiceCertsDataSource() datasource.DataSource {
	return &serviceCertsDataSource{}
}

type serviceCertsDataSource struct {
	client client.ClientInterface
}

type serviceCertsDataSourceModel struct {
	ServiceCerts []serviceCertDataSourceModel `tfsdk:"service_certs"`
}

func (d *serviceCertsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_certs"
}

func (d *serviceCertsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of all service certificates configured in ClearPass. " +
			"Service certificates are used for RADIUS, HTTPS, and other TLS-based services.",
		Attributes: map[string]schema.Attribute{
			"service_certs": schema.ListNestedAttribute{
				MarkdownDescription: "List of service certificates.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							MarkdownDescription: "Numeric ID of the service certificate.",
							Computed:            true,
						},
						"subject": schema.StringAttribute{
							MarkdownDescription: "The Subject Distinguished Name (DN) of the certificate.",
							Computed:            true,
						},
						"expiry_date": schema.StringAttribute{
							MarkdownDescription: "The expiration date of the certificate.",
							Computed:            true,
						},
						"issue_date": schema.StringAttribute{
							MarkdownDescription: "The date the certificate was issued.",
							Computed:            true,
						},
						"issue_by": schema.StringAttribute{
							MarkdownDescription: "The Certificate Authority (CA) or issuer that signed the certificate.",
							Computed:            true,
						},
						"validity": schema.StringAttribute{
							MarkdownDescription: "The validity status of the certificate (e.g., `Valid`, `Expired`).",
							Computed:            true,
						},
						"cert_file": schema.StringAttribute{
							MarkdownDescription: "The certificate file name as stored in ClearPass.",
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

func (d *serviceCertsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *serviceCertsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state serviceCertsDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	limit := 1000
	certList, err := d.client.GetServiceCerts(ctx, nil, nil, nil, &limit, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Service Certificates",
			"Could not read ClearPass Service Certificates: "+err.Error(),
		)
		return
	}

	if certList == nil {
		resp.Diagnostics.AddError(
			"ClearPass Service Certificates Not Found",
			"No Service Certificates returned",
		)
		return
	}

	for _, cert := range certList.Embedded.Items {
		state.ServiceCerts = append(state.ServiceCerts, serviceCertDataSourceModel{
			ID:         types.Int64Value(int64(cert.ID)),
			Subject:    types.StringValue(cert.Subject),
			ExpiryDate: types.StringValue(cert.ExpiryDate),
			IssueDate:  types.StringValue(cert.IssueDate),
			IssueBy:    types.StringValue(cert.IssueBy),
			Validity:   types.StringValue(cert.Validity),
			CertFile:   types.StringValue(cert.CertFile),
		})
	}

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
