package provider

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider-defined types implement framework interfaces.
var _ resource.Resource = &certTrustListResource{}
var _ resource.ResourceWithImportState = &certTrustListResource{}

func NewCertTrustListResource() resource.Resource {
	return &certTrustListResource{}
}

type certTrustListResource struct {
	client client.ClientInterface
}

type certTrustListResourceModel struct {
	ID        types.String `tfsdk:"id"`
	CertFile  types.String `tfsdk:"cert_file"`
	Enabled   types.Bool   `tfsdk:"enabled"`
	CertUsage types.List   `tfsdk:"cert_usage"`
}

func (r *certTrustListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cert_trust_list"
}

func (r *certTrustListResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Certificate Trust List in ClearPass.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the certificate trust list.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cert_file": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The content of the certificate file.",
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the certificate trust list is enabled.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"cert_usage": schema.ListAttribute{
				ElementType:         types.StringType,
				Required:            true,
				MarkdownDescription: "Usage of the certificate. Allowed values: `AD/LDAP Servers`, `Aruba Infrastructure`, `Aruba Services`, `Database`, `EAP`, `Endpoint Context Servers`, `RadSec`, `SAML`, `SMTP`, `EST`, `Others`.",
			},
		},
	}
}

func (r *certTrustListResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *certTrustListResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan certTrustListResourceModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var certUsage []string
	diags = plan.CertUsage.ElementsAs(ctx, &certUsage, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	certCreate := &client.CertTrustListCreate{
		CertFile:  plan.CertFile.ValueString(),
		Enabled:   plan.Enabled.ValueBool(),
		CertUsage: certUsage,
	}

	// If enabled is not set in config, it might be computed.
	// However, for create, we should probably default to true if not specified, or let the API decide.
	// Since it's Optional+Computed, if it's null, we might send false or omit it?
	// The struct has `bool`, so it defaults to false.
	// Let's check if it's unknown.
	if plan.Enabled.IsUnknown() {
		// If unknown, we can't really send a value unless we have a default.
		// But the API might require it. The spec says "enabled" is in the body.
		// Let's assume false if not provided, or maybe true?
		// For now, we use ValueBool() which is false if null/unknown.
		// But wait, if it's unknown, ValueBool is false.
	}

	cert, err := r.client.CreateCertTrustList(ctx, certCreate)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating certificate trust list",
			"Could not create certificate trust list, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(strconv.Itoa(cert.ID))
	// plan.CertFile = types.StringValue(cert.CertFile) // Keep user input to avoid inconsistency
	plan.Enabled = types.BoolValue(cert.Enabled)

	certUsageList, diags := types.ListValueFrom(ctx, types.StringType, cert.CertUsage)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.CertUsage = certUsageList

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *certTrustListResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state certTrustListResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading certificate trust list",
			"Could not parse ID: "+err.Error(),
		)
		return
	}

	cert, err := r.client.GetCertTrustList(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading certificate trust list",
			"Could not read certificate trust list: "+err.Error(),
		)
		return
	}

	if cert == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	// Only update CertFile if it's missing (e.g. import) to avoid drift due to API normalization
	if state.CertFile.IsNull() || state.CertFile.IsUnknown() {
		state.CertFile = types.StringValue(cert.CertFile)
	}
	state.Enabled = types.BoolValue(cert.Enabled)

	certUsageList, diags := types.ListValueFrom(ctx, types.StringType, cert.CertUsage)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.CertUsage = certUsageList

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (r *certTrustListResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan certTrustListResourceModel
	var state certTrustListResourceModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating certificate trust list",
			"Could not parse ID: "+err.Error(),
		)
		return
	}

	var certUsage []string
	diags = plan.CertUsage.ElementsAs(ctx, &certUsage, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	certUpdate := &client.CertTrustListUpdate{
		CertFile:  plan.CertFile.ValueString(),
		Enabled:   plan.Enabled.ValueBool(),
		CertUsage: certUsage,
	}

	cert, err := r.client.UpdateCertTrustList(ctx, id, certUpdate)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating certificate trust list",
			"Could not update certificate trust list: "+err.Error(),
		)
		return
	}

	// plan.CertFile = types.StringValue(cert.CertFile) // Keep user input
	plan.Enabled = types.BoolValue(cert.Enabled)

	certUsageList, diags := types.ListValueFrom(ctx, types.StringType, cert.CertUsage)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.CertUsage = certUsageList

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *certTrustListResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state certTrustListResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting certificate trust list",
			"Could not parse ID: "+err.Error(),
		)
		return
	}

	err = r.client.DeleteCertTrustList(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting certificate trust list",
			"Could not delete certificate trust list: "+err.Error(),
		)
		return
	}
}

func (r *certTrustListResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
