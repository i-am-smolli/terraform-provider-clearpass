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
		Description: "Manages a service certificate in ClearPass.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Numeric ID of the service certificate.",
				Required:    true,
			},
			"subject": schema.StringAttribute{
				Description: "Subject of the service certificate.",
				Computed:    true,
			},
			"expiry_date": schema.StringAttribute{
				Description: "Expiry date of the service certificate.",
				Computed:    true,
			},
			"issue_date": schema.StringAttribute{
				Description: "Issue date of the service certificate.",
				Computed:    true,
			},
			"issue_by": schema.StringAttribute{
				Description: "Service certificate issued by.",
				Computed:    true,
			},
			"validity": schema.StringAttribute{
				Description: "Validity of the service certificate.",
				Computed:    true,
			},
			"cert_file": schema.StringAttribute{
				Description: "Certificate File.",
				Computed:    true,
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
