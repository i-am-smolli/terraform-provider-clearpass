package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ resource.Resource = &extensionInstanceConfigResource{}
var _ resource.ResourceWithImportState = &extensionInstanceConfigResource{}

type extensionInstanceConfigResource struct {
	client client.ClientInterface
}

type extensionInstanceConfigModel struct {
	ID         types.String `tfsdk:"id"`
	InstanceID types.String `tfsdk:"instance_id"`
	ConfigJSON types.String `tfsdk:"config_json"`
}

func NewExtensionInstanceConfigResource() resource.Resource {
	return &extensionInstanceConfigResource{}
}

func (r *extensionInstanceConfigResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_extension_instance_config"
}

func (r *extensionInstanceConfigResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the configuration of an installed ClearPass Extension Instance. " +
			"Only extensions marked with `has_config: true` support configuration. " +
			"The configuration is an arbitrary JSON object specific to each extension — consult the extension's documentation for available settings. " +
			"Destroying this resource removes it from Terraform state only; there is no API endpoint to delete an extension's configuration.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Identifier for this resource. Equals `instance_id`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"instance_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ID of the extension instance whose configuration is managed.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"config_json": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The configuration for the extension as a JSON-encoded string. The value is stored in normalized (compacted) form to prevent spurious diffs.",
			},
		},
	}
}

func (r *extensionInstanceConfigResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	c, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected client.ClientInterface, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = c
}

func (r *extensionInstanceConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data extensionInstanceConfigModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	normalizedConfig, err := normalizeJSON(data.ConfigJSON.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid config_json", fmt.Sprintf("config_json must be valid JSON: %s", err))
		return
	}

	result, err := r.client.SetExtensionInstanceConfig(ctx, data.InstanceID.ValueString(), json.RawMessage(normalizedConfig))
	if err != nil {
		resp.Diagnostics.AddError("Failed to set extension instance config", err.Error())
		return
	}

	data.ID = data.InstanceID
	data.ConfigJSON = configFromResult(result, normalizedConfig)

	tflog.Trace(ctx, fmt.Sprintf("Created extension instance config for instance ID: %s", data.InstanceID.ValueString()))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *extensionInstanceConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data extensionInstanceConfigModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.client.GetExtensionInstanceConfig(ctx, data.InstanceID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read extension instance config", err.Error())
		return
	}

	if result == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	normalized, err := normalizeJSON(string(result))
	if err != nil {
		resp.Diagnostics.AddError("Unexpected API response", fmt.Sprintf("API returned invalid JSON for config: %s", err))
		return
	}

	data.ConfigJSON = types.StringValue(normalized)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *extensionInstanceConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data extensionInstanceConfigModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	normalizedConfig, err := normalizeJSON(data.ConfigJSON.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid config_json", fmt.Sprintf("config_json must be valid JSON: %s", err))
		return
	}

	result, err := r.client.SetExtensionInstanceConfig(ctx, data.InstanceID.ValueString(), json.RawMessage(normalizedConfig))
	if err != nil {
		resp.Diagnostics.AddError("Failed to update extension instance config", err.Error())
		return
	}

	data.ConfigJSON = configFromResult(result, normalizedConfig)

	tflog.Trace(ctx, fmt.Sprintf("Updated extension instance config for instance ID: %s", data.InstanceID.ValueString()))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *extensionInstanceConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// There is no API endpoint to delete an extension's configuration.
	// Removing this resource from Terraform state is sufficient.
	tflog.Trace(ctx, "Removed extension instance config from state (no API delete endpoint exists)")
}

func (r *extensionInstanceConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by extension instance ID — sets both id and instance_id.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("instance_id"), req.ID)...)
}

// normalizeJSON unmarshals then re-marshals JSON so that map keys are sorted
// alphabetically. This produces a stable, canonical representation that is
// independent of the original key order, preventing spurious diffs between the
// value written by the user (e.g. via jsonencode) and the value returned by the
// API.
func normalizeJSON(in string) (string, error) {
	var v interface{}
	if err := json.Unmarshal([]byte(in), &v); err != nil {
		return "", err
	}
	out, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// configFromResult returns the normalized JSON config from the API result, falling
// back to the sent value when the API responds with an empty body (HTTP 204/empty).
func configFromResult(result json.RawMessage, fallback string) types.String {
	if len(result) == 0 {
		return types.StringValue(fallback)
	}
	normalized, err := normalizeJSON(string(result))
	if err != nil {
		return types.StringValue(fallback)
	}
	return types.StringValue(normalized)
}
