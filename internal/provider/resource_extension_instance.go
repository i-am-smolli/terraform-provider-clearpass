package provider

import (
	"context"
	"fmt"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ resource.Resource = &extensionInstanceResource{}
var _ resource.ResourceWithImportState = &extensionInstanceResource{}

type extensionInstanceResource struct {
	client client.ClientInterface
}

type extensionInstanceModel struct {
	ID               types.String `tfsdk:"id"`
	State            types.String `tfsdk:"state"`
	StateDetails     types.String `tfsdk:"state_details"`
	StoreID          types.String `tfsdk:"store_id"`
	Name             types.String `tfsdk:"name"`
	Version          types.String `tfsdk:"version"`
	Description      types.String `tfsdk:"description"`
	IconHref         types.String `tfsdk:"icon_href"`
	AboutHref        types.String `tfsdk:"about_href"`
	Hostname         types.String `tfsdk:"hostname"`
	InternalIPAddr   types.String `tfsdk:"internal_ip_address"`
	NeedsReinstall   types.Bool   `tfsdk:"needs_reinstall"`
	ReinstallDetails types.String `tfsdk:"reinstall_details"`
	HasConfig        types.Bool   `tfsdk:"has_config"`
	InstallTime      types.String `tfsdk:"install_time"`
	Note             types.String `tfsdk:"note"`
	Upgrade          types.String `tfsdk:"upgrade"`
}

func NewExtensionInstanceResource() resource.Resource {
	return &extensionInstanceResource{}
}

func (r *extensionInstanceResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_extension_instance"
}

func (r *extensionInstanceResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a ClearPass Extension Instance. Extensions provide additional functionality to ClearPass by running in isolated containers.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ID of the extension instance",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"store_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ID from the extension store",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"state": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("stopped"),
				MarkdownDescription: "Desired state of the extension. Valid values are 'stopped' or 'running'.",
				Validators: []validator.String{
					stringvalidator.OneOf("stopped", "running"),
				},
			},
			"name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Name of the extension",
			},
			"version": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Version number of the extension",
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Description of the extension",
			},
			"icon_href": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "URL for the extension's icon",
			},
			"about_href": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "URL for the extension's documentation",
			},
			"hostname": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Hostname assigned to the extension",
			},
			"internal_ip_address": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Internal IP address of the extension",
			},
			"needs_reinstall": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Indicates if the extension is out-of-date and should be reinstalled",
			},
			"reinstall_details": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "State details for any background reinstall operation in progress",
			},
			"has_config": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Indicates that the extension has configuration settings",
			},
			"install_time": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Time at which the extension was installed",
			},
			"note": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "A user note about the extension displayed in the UI",
			},
			"state_details": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Additional information about the current state of the extension",
			},
			"upgrade": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Indicates whether a major or minor upgrade is available",
			},
		},
	}
}

func (r *extensionInstanceResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *extensionInstanceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data extensionInstanceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the API request payload
	extCreate := &client.ExtensionInstanceCreate{
		StoreID: data.StoreID.ValueString(),
		State:   data.State.ValueString(),
		Note:    data.Note.ValueString(),
	}

	// Call the API
	extResult, err := r.client.CreateExtensionInstance(ctx, extCreate)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create extension instance", err.Error())
		return
	}

	// Map the API response to the model
	r.apiResultToModel(extResult, &data)

	tflog.Trace(ctx, fmt.Sprintf("Created extension instance with ID: %s", data.ID.ValueString()))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *extensionInstanceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data extensionInstanceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Call the API
	extResult, err := r.client.GetExtensionInstance(ctx, data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read extension instance", err.Error())
		return
	}

	// If the resource was deleted, remove from state
	if extResult == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	// Map the API response to the model
	r.apiResultToModel(extResult, &data)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *extensionInstanceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data extensionInstanceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the API request payload
	extModify := &client.ExtensionInstanceModify{
		State: data.State.ValueString(),
		Note:  data.Note.ValueString(),
	}

	// Call the API
	extResult, err := r.client.UpdateExtensionInstance(ctx, data.ID.ValueString(), extModify)
	if err != nil {
		resp.Diagnostics.AddError("Failed to update extension instance", err.Error())
		return
	}

	// Map the API response to the model
	r.apiResultToModel(extResult, &data)

	tflog.Trace(ctx, fmt.Sprintf("Updated extension instance with ID: %s", data.ID.ValueString()))

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *extensionInstanceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data extensionInstanceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Call the API
	err := r.client.DeleteExtensionInstance(ctx, data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to delete extension instance", err.Error())
		return
	}

	tflog.Trace(ctx, fmt.Sprintf("Deleted extension instance with ID: %s", data.ID.ValueString()))
}

func (r *extensionInstanceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Use the extension ID as the import identifier
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// Helper function to map API response to Terraform model.
func (r *extensionInstanceResource) apiResultToModel(apiResult *client.ExtensionInstanceResult, model *extensionInstanceModel) {
	model.ID = types.StringValue(apiResult.ID)
	model.State = types.StringValue(apiResult.State)
	model.StateDetails = types.StringValue(apiResult.StateDetails)
	model.StoreID = types.StringValue(apiResult.StoreID)
	model.Name = types.StringValue(apiResult.Name)
	model.Version = types.StringValue(apiResult.Version)
	model.Description = types.StringValue(apiResult.Description)
	model.IconHref = types.StringValue(apiResult.IconHref)
	model.AboutHref = types.StringValue(apiResult.AboutHref)
	model.Hostname = types.StringValue(apiResult.Hostname)
	model.InternalIPAddr = types.StringValue(apiResult.InternalIPAddr)
	model.NeedsReinstall = types.BoolValue(apiResult.NeedsReinstall)
	model.ReinstallDetails = types.StringValue(apiResult.ReinstallDetails)
	model.HasConfig = types.BoolValue(apiResult.HasConfig)
	model.InstallTime = types.StringValue(apiResult.InstallTime)
	model.Note = types.StringValue(apiResult.Note)
	model.Upgrade = types.StringValue(apiResult.Upgrade)
}
