package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	Port             types.Int64  `tfsdk:"port"`
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
				Description: "The URL to the PKCS12 file to be uploaded. Mutually exclusive with `pkcs12_file_base64`.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(path.MatchRoot("pkcs12_file_base64")),
				},
			},
			"pkcs12_file_base64": schema.StringAttribute{
				Description: "Base64 encoded content of the PFX file. Use filebase64() in HCL. When used, the provider spawns a temporary local HTTP server to serve the file to ClearPass. Mutually exclusive with `pkcs12_file_url`.",
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
			"port": schema.Int64Attribute{
				Description: "The port to use for the temporary HTTP server. If not specified, a random port is used.",
				Optional:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
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

// Finds the preferred outbound IP for the target.
func getOutboundIP(targetHost string) (net.IP, error) {
	// Add default port if none is present (required for Dial)
	address := targetHost
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(address, "443")
	}

	// This call does not establish a real connection, it only queries the routing system
	conn, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("failed to cast local address to UDPAddr")
	}
	return localAddr.IP, nil
}

func (r *serviceCertResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serviceCertResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	finalUrl := plan.PKCS12FileURL.ValueString()

	// Logic: If URL is empty, but Base64 content is present -> start server
	if finalUrl == "" && !plan.PKCS12FileBase64.IsNull() {

		// 1. Get Base64 content
		b64Content := plan.PKCS12FileBase64.ValueString()
		// Decode to ensure clean bytes (optional, but good for Content-Length)
		certBytes, err := base64.StdEncoding.DecodeString(b64Content)
		if err != nil {
			resp.Diagnostics.AddError("Base64 Decode Error", err.Error())
			return
		}

		// 2. Start temporary listener
		listenAddr := ":0"
		if !plan.Port.IsNull() && plan.Port.ValueInt64() > 0 {
			listenAddr = fmt.Sprintf(":%d", plan.Port.ValueInt64())
		}
		listener, err := net.Listen("tcp", listenAddr)
		if err != nil {
			resp.Diagnostics.AddError("Failed to start temp server", err.Error())
			return
		}
		tcpAddr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			resp.Diagnostics.AddError("Networking Error", "Failed to cast listener address to TCPAddr")
			return
		}
		port := tcpAddr.Port

		// 3. Define HTTP handler
		// We serve the file under a random path or simply root
		mux := http.NewServeMux()
		downloadChan := make(chan bool, 1)
		mux.HandleFunc("/cert.pfx", func(w http.ResponseWriter, r *http.Request) {
			// Notify that ClearPass hit the endpoint
			select {
			case downloadChan <- true:
			default:
			}

			w.Header().Set("Content-Type", "application/x-pkcs12")
			w.Header().Set("Content-Length", strconv.Itoa(len(certBytes)))
			_, _ = w.Write(certBytes) // Ignore error writing to response
		})

		server := &http.Server{Handler: mux}

		// Start server in goroutine
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				// Log error if needed, but we can't do much here as it's async
				fmt.Printf("Temp server error: %v\n", err)
			}
		}()
		// IMPORTANT: Gracefully shut down server at the end so active downloads aren't interrupted.
		// We wait for the endpoint to be hit first (up to 15 seconds) because ClearPass might fetch it asynchronously.
		defer func() {
			select {
			case <-downloadChan:
				// Download initiated, now we let graceful shutdown wait for the client to finish downloading
			case <-time.After(15 * time.Second):
				// Timeout waiting for ClearPass to fetch the cert. Proceed to shutdown to prevent hanging forever.
			}

			ctxShutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = server.Shutdown(ctxShutdown)
		}()

		// 4. Determine IP (based on route to ClearPass Host)
		targetHost := r.client.GetHost()
		myIP, err := getOutboundIP(targetHost)
		if err != nil {
			resp.Diagnostics.AddError("Networking Error", "Could not determine local IP for ClearPass callback. "+err.Error())
			return
		}

		// 5. Build URL (http://<IP>:<PORT>/cert.pfx)
		// Note: If ClearPass enforces HTTPS, we have a problem.
		// But mostly they accept HTTP for import.
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
	// Normalize subject: remove spaces after commas
	normalizedSubject := strings.ReplaceAll(result.Subject, ", ", ",")
	plan.Subject = types.StringValue(normalizedSubject)
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
	// Normalize subject: remove spaces after commas
	normalizedSubject := strings.ReplaceAll(result.Subject, ", ", ",")
	state.Subject = types.StringValue(normalizedSubject)
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
