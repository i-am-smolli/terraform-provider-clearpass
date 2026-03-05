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
	_ datasource.DataSource              = &serviceCertDataSource{}
	_ datasource.DataSourceWithConfigure = &serviceCertDataSource{}
)

func NewServiceCertDataSource() datasource.DataSource {
	return &serviceCertDataSource{}
}

type serviceCertDataSource struct {
	client client.ClientInterface
}

type serviceCertDataSourceModel struct {
	ID         types.Int64  `tfsdk:"id"`
	Subject    types.String `tfsdk:"subject"`
	ExpiryDate types.String `tfsdk:"expiry_date"`
	IssueDate  types.String `tfsdk:"issue_date"`
	IssueBy    types.String `tfsdk:"issue_by"`
	Validity   types.String `tfsdk:"validity"`
	CertFile   types.String `tfsdk:"cert_file"`
}

func (d *serviceCertDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_cert"
}

func (d *serviceCertDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves the details of a specific service certificate in ClearPass by its numeric ID. " +
			"Service certificates are used for RADIUS, HTTPS, and other TLS-based services.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				MarkdownDescription: "Numeric ID of the service certificate to retrieve.",
				Required:            true,
			},
			"subject": schema.StringAttribute{
				MarkdownDescription: "The Subject Distinguished Name (DN) of the certificate (e.g., `CN=clearpass.example.com`).",
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
	}
}

func (d *serviceCertDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *serviceCertDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state serviceCertDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cert, err := d.client.GetServiceCert(ctx, int(state.ID.ValueInt64()))

	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Service Certificate",
			"Could not read ClearPass Service Certificate ID "+state.ID.String()+": "+err.Error(),
		)
		return
	}

	if cert == nil {
		resp.Diagnostics.AddError(
			"ClearPass Service Certificate Not Found",
			fmt.Sprintf("Service Certificate with ID %d not found", state.ID.ValueInt64()),
		)
		return
	}

	state.ID = types.Int64Value(int64(cert.ID))
	state.Subject = types.StringValue(cert.Subject)
	state.ExpiryDate = types.StringValue(cert.ExpiryDate)
	state.IssueDate = types.StringValue(cert.IssueDate)
	state.IssueBy = types.StringValue(cert.IssueBy)
	state.Validity = types.StringValue(cert.Validity)
	state.CertFile = types.StringValue(cert.CertFile)

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
