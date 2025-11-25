package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider-defined types implement framework interfaces.
var _ resource.Resource = &serviceCertResource{}
var _ resource.ResourceWithImportState = &serviceCertResource{}

func NewServiceCertResource() resource.Resource {
	return &serviceCertResource{}
}

type serviceCertResource struct {
	client client.ClientInterface
}

type serviceCertResourceModel struct {
	ID               types.Int64  `tfsdk:"id"`
	CertificateURL   types.String `tfsdk:"certificate_url"`
	PKCS12FileURL    types.String `tfsdk:"pkcs12_file_url"`
	PKCS12FileBase64 types.String `tfsdk:"pkcs12_file_base64"`
	PKCS12Passphrase types.String `tfsdk:"pkcs12_passphrase"`
	Subject          types.String `tfsdk:"subject"`
	ExpiryDate       types.String `tfsdk:"expiry_date"`
	IssueDate        types.String `tfsdk:"issue_date"`
	IssueBy          types.String `tfsdk:"issue_by"`
	Validity         types.String `tfsdk:"validity"`
	CertFile         types.String `tfsdk:"cert_file"`
}

func (r *serviceCertResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_cert"
}

func (r *serviceCertResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Service Certificate in ClearPass. Service certificates are used for secure communication and authentication.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Numeric ID of the service certificate.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"certificate_url": schema.StringAttribute{
				Description: "The URL to the certificate file to be uploaded.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"pkcs12_file_url": schema.StringAttribute{
				Description: "The URL to the PKCS12 file to be uploaded.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(path.MatchRoot("pkcs12_file_base64")),
				},
			},
			"pkcs12_file_base64": schema.StringAttribute{
				Description: "Base64 encoded content of the PFX file. Use filebase64() in HCL.",
				Optional:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(path.MatchRoot("pkcs12_file_url")),
				},
			},
			"pkcs12_passphrase": schema.StringAttribute{
				Description: "The passphrase for the PKCS12 file.",
				Optional:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"subject": schema.StringAttribute{
				Description: "The subject of the certificate.",
				Computed:    true,
			},
			"expiry_date": schema.StringAttribute{
				Description: "The expiry date of the certificate.",
				Computed:    true,
			},
			"issue_date": schema.StringAttribute{
				Description: "The issue date of the certificate.",
				Computed:    true,
			},
			"issue_by": schema.StringAttribute{
				Description: "The issuer of the certificate.",
				Computed:    true,
			},
			"validity": schema.StringAttribute{
				Description: "The validity period of the certificate.",
				Computed:    true,
			},
			"cert_file": schema.StringAttribute{
				Description: "The content of the certificate file.",
				Computed:    true,
			},
		},
	}
}

func (r *serviceCertResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected client.ClientInterface, got: %T.", req.ProviderData),
		)
		return
	}
	r.client = client
}

// Findet die bevorzugte ausgehende IP
func getOutboundIP() (net.IP, error) {
	// Dieser Call baut keine echte Verbindung auf, er fragt nur das Routing-System,
	// welches Interface für diese Ziel-IP genutzt würde.
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

func (r *serviceCertResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serviceCertResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	finalUrl := plan.PKCS12FileURL.ValueString()

	// Logik: Wenn URL leer ist, aber Base64 Content da ist -> Server starten
	if finalUrl == "" && !plan.PKCS12FileBase64.IsNull() {

		// 1. Base64 Content holen
		b64Content := plan.PKCS12FileBase64.ValueString()
		// Dekodieren, um sicherzugehen, dass es saubere Bytes sind (optional, aber gut für Content-Length)
		certBytes, err := base64.StdEncoding.DecodeString(b64Content)
		if err != nil {
			resp.Diagnostics.AddError("Base64 Decode Error", err.Error())
			return
		}

		// 2. Temporären Listener auf Port 0 (Zufall) starten
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			resp.Diagnostics.AddError("Failed to start temp server", err.Error())
			return
		}
		port := listener.Addr().(*net.TCPAddr).Port

		// 3. HTTP Handler definieren
		// Wir servieren das File unter einem zufälligen Pfad oder einfach Root
		mux := http.NewServeMux()
		mux.HandleFunc("/cert.pfx", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/x-pkcs12")
			w.Write(certBytes)
		})

		server := &http.Server{Handler: mux}

		// Server in Goroutine starten
		go func() {
			server.Serve(listener)
		}()
		// WICHTIG: Server am Ende killen
		defer server.Close()

		// 4. IP ermitteln
		myIP, err := getOutboundIP()
		if err != nil {
			resp.Diagnostics.AddError("Networking Error", "Could not determine local IP for ClearPass callback. "+err.Error())
			return
		}

		// 5. URL bauen (http://<IP>:<PORT>/cert.pfx)
		// Achtung: Wenn ClearPass HTTPS erzwingt, haben wir ein Problem.
		// Aber meistens akzeptieren sie HTTP für den Import.
		finalUrl = fmt.Sprintf("http://%s:%d/cert.pfx", myIP.String(), port)
	}

	apiPayload := &client.ServiceCertCreate{
		CertificateURL:   plan.CertificateURL.ValueString(),
		PKCS12FileURL:    finalUrl,
		PKCS12Passphrase: plan.PKCS12Passphrase.ValueString(),
	}

	result, err := r.client.CreateServiceCert(ctx, apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to create service cert: %s", err))
		return
	}

	plan.ID = types.Int64Value(int64(result.ID))
	plan.Subject = types.StringValue(result.Subject)
	plan.ExpiryDate = types.StringValue(result.ExpiryDate)
	plan.IssueDate = types.StringValue(result.IssueDate)
	plan.IssueBy = types.StringValue(result.IssueBy)
	plan.Validity = types.StringValue(result.Validity)
	plan.CertFile = types.StringValue(result.CertFile)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceCertResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serviceCertResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueInt64()
	result, err := r.client.GetServiceCert(ctx, int(id))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to read service cert: %s", err))
		return
	}

	if result == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.Int64Value(int64(result.ID))
	state.Subject = types.StringValue(result.Subject)
	state.ExpiryDate = types.StringValue(result.ExpiryDate)
	state.IssueDate = types.StringValue(result.IssueDate)
	state.IssueBy = types.StringValue(result.IssueBy)
	state.Validity = types.StringValue(result.Validity)
	state.CertFile = types.StringValue(result.CertFile)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *serviceCertResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Update is not supported by the API for this resource.
	// All fields are marked as RequiresReplace, so Terraform should not call this method.
	resp.Diagnostics.AddError("Operation Not Supported", "Update operation is not supported for this resource.")
}

func (r *serviceCertResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serviceCertResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueInt64()
	err := r.client.DeleteServiceCert(ctx, int(id))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to delete service cert: %s", err))
		return
	}
}

func (r *serviceCertResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", fmt.Sprintf("Expected numeric ID, got %s", req.ID))
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}
