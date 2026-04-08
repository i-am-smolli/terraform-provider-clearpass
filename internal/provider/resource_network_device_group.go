// internal/provider/resource_network_device_group.go
package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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
var _ resource.Resource = &networkDeviceGroupResource{}

// networkDeviceGroupResource defines the resource implementation.
type networkDeviceGroupResource struct {
	client client.ClientInterface
}

// networkDeviceGroupResourceModel defines the HCL data model for the resource.
type networkDeviceGroupResourceModel struct {
	ID          types.Int64  `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	GroupFormat types.String `tfsdk:"group_format"`
	Value       types.String `tfsdk:"value"`
	Devices     types.List   `tfsdk:"devices"`
}

// NewNetworkDeviceGroupResource is a factory function for the networkDeviceGroupResource.
func NewNetworkDeviceGroupResource() resource.Resource {
	return &networkDeviceGroupResource{}
}

// Metadata returns the resource type name.
func (r *networkDeviceGroupResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_device_group"
}

// Schema defines the HCL attributes for the resource.
func (r *networkDeviceGroupResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a network device group in ClearPass. Network device groups allow you to " +
			"organize network devices by subnet, regular expression pattern, or explicit list. " +
			"Groups are referenced by enforcement profiles to target specific sets of devices.",

		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Numeric ID of the network device group assigned by ClearPass.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Unique name of the network device group.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the network device group.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"group_format": schema.StringAttribute{
				Description: "Format of the network devices in this group. Must be one of: `subnet`, `regex`, `list`.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("subnet", "regex", "list"),
				},
			},
			"value": schema.StringAttribute{
				Description: "Network devices in the specified format. For `subnet`, use CIDR notation (e.g., `10.0.0.0/8`). " +
					"For `regex`, use a regular expression pattern. For `list`, use a comma-separated list of IP addresses or set `devices`.",
				Optional: true,
				Computed: true,
			},
			"devices": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "List of network devices. Only applicable when `group_format` is `list`. " +
					"When specified, this takes precedence over the `value` field for creating/updating the resource.",
				Optional: true,
				Computed: true,
			},
		},
	}
}

// Configure passes the API client to the resource.
func (r *networkDeviceGroupResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected client.ClientInterface, got: %T. Please report this issue to the provider developer.", req.ProviderData),
		)
		return
	}
	r.client = client
}

// Create is called when the resource is created.
func (r *networkDeviceGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan networkDeviceGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	value := ""
	if !plan.Value.IsNull() && !plan.Value.IsUnknown() {
		value = strings.TrimSpace(plan.Value.ValueString())
	}

	// If devices list is provided and group_format is "list", convert to comma-separated value
	if plan.GroupFormat.ValueString() == "list" && !plan.Devices.IsNull() && !plan.Devices.IsUnknown() && len(plan.Devices.Elements()) > 0 {
		devices := make([]string, 0, len(plan.Devices.Elements()))
		resp.Diagnostics.Append(plan.Devices.ElementsAs(ctx, &devices, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		value = strings.Join(devices, ", ")
	}

	if plan.GroupFormat.ValueString() == "list" && value == "" {
		resp.Diagnostics.AddError(
			"Missing Configuration",
			"For group_format 'list', configure either 'devices' or 'value'.",
		)
		return
	}

	if plan.GroupFormat.ValueString() != "list" && value == "" {
		resp.Diagnostics.AddError(
			"Missing Configuration",
			"Attribute 'value' is required when group_format is 'subnet' or 'regex'.",
		)
		return
	}

	apiPayload := &client.NetworkDeviceGroupCreate{
		Name:        plan.Name.ValueString(),
		GroupFormat: plan.GroupFormat.ValueString(),
		Value:       value,
	}
	if !plan.Description.IsNull() {
		apiPayload.Description = plan.Description.ValueString()
	}

	created, err := r.client.CreateNetworkDeviceGroup(ctx, apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to create network device group: %s", err))
		return
	}

	// Save API response back to state
	plan.ID = types.Int64Value(int64(created.ID))
	plan.Name = types.StringValue(created.Name)
	plan.Description = types.StringValue(created.Description)
	plan.GroupFormat = types.StringValue(created.GroupFormat)
	plan.Value = types.StringValue(created.Value)

	// Parse value into devices if format is list
	if created.GroupFormat == "list" {
		deviceList := strings.Split(created.Value, ",")
		devices := make([]attr.Value, 0, len(deviceList))
		for _, d := range deviceList {
			trimmed := strings.TrimSpace(d)
			if trimmed == "" {
				continue
			}
			devices = append(devices, types.StringValue(trimmed))
		}
		plan.Devices = types.ListValueMust(types.StringType, devices)
	} else {
		plan.Devices = types.ListNull(types.StringType)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read is called to refresh the resource state.
func (r *networkDeviceGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state networkDeviceGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	numericID := state.ID.ValueInt64()
	group, err := r.client.GetNetworkDeviceGroup(ctx, int(numericID))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to read network device group: %s", err))
		return
	}

	if group == nil {
		resp.Diagnostics.AddWarning("Resource Not Found", "Network device group not found, removing from state.")
		resp.State.RemoveResource(ctx)
		return
	}

	// Refresh state with data from API
	state.ID = types.Int64Value(int64(group.ID))
	state.Name = types.StringValue(group.Name)
	state.Description = types.StringValue(group.Description)
	state.GroupFormat = types.StringValue(group.GroupFormat)
	state.Value = types.StringValue(group.Value)

	// Parse value into devices if format is list
	if group.GroupFormat == "list" {
		deviceList := strings.Split(group.Value, ",")
		devices := make([]attr.Value, 0, len(deviceList))
		for _, d := range deviceList {
			trimmed := strings.TrimSpace(d)
			if trimmed == "" {
				continue
			}
			devices = append(devices, types.StringValue(trimmed))
		}
		state.Devices = types.ListValueMust(types.StringType, devices)
	} else {
		state.Devices = types.ListNull(types.StringType)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is called when the resource is updated.
func (r *networkDeviceGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan networkDeviceGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPayload := &client.NetworkDeviceGroupUpdate{}
	if !plan.Name.IsUnknown() {
		apiPayload.Name = plan.Name.ValueString()
	}
	if !plan.Description.IsUnknown() {
		apiPayload.Description = plan.Description.ValueString()
	}
	if !plan.GroupFormat.IsUnknown() {
		apiPayload.GroupFormat = plan.GroupFormat.ValueString()
	}
	value := ""
	if !plan.Value.IsNull() && !plan.Value.IsUnknown() {
		value = strings.TrimSpace(plan.Value.ValueString())
	}

	// Handle value/devices: if devices list is provided and group_format is "list", use that
	if plan.GroupFormat.ValueString() == "list" && !plan.Devices.IsNull() && !plan.Devices.IsUnknown() && len(plan.Devices.Elements()) > 0 {
		devices := make([]string, 0, len(plan.Devices.Elements()))
		resp.Diagnostics.Append(plan.Devices.ElementsAs(ctx, &devices, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		value = strings.Join(devices, ", ")
	}

	if plan.GroupFormat.ValueString() == "list" && value == "" {
		resp.Diagnostics.AddError(
			"Missing Configuration",
			"For group_format 'list', configure either 'devices' or 'value'.",
		)
		return
	}

	if plan.GroupFormat.ValueString() != "list" && value == "" {
		resp.Diagnostics.AddError(
			"Missing Configuration",
			"Attribute 'value' is required when group_format is 'subnet' or 'regex'.",
		)
		return
	}

	apiPayload.Value = value

	numericID := plan.ID.ValueInt64()
	updated, err := r.client.UpdateNetworkDeviceGroup(ctx, int(numericID), apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to update network device group: %s", err))
		return
	}

	// Save updated data to state
	plan.ID = types.Int64Value(int64(updated.ID))
	plan.Name = types.StringValue(updated.Name)
	plan.Description = types.StringValue(updated.Description)
	plan.GroupFormat = types.StringValue(updated.GroupFormat)
	plan.Value = types.StringValue(updated.Value)

	// Parse value into devices if format is list
	if updated.GroupFormat == "list" {
		deviceList := strings.Split(updated.Value, ",")
		devices := make([]attr.Value, 0, len(deviceList))
		for _, d := range deviceList {
			trimmed := strings.TrimSpace(d)
			if trimmed == "" {
				continue
			}
			devices = append(devices, types.StringValue(trimmed))
		}
		plan.Devices = types.ListValueMust(types.StringType, devices)
	} else {
		plan.Devices = types.ListNull(types.StringType)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete is called when the resource is destroyed.
func (r *networkDeviceGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state networkDeviceGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	numericID := state.ID.ValueInt64()
	err := r.client.DeleteNetworkDeviceGroup(ctx, int(numericID))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to delete network device group with ID %d: %s", numericID, err))
		return
	}
}

func (r *networkDeviceGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	numericID, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected a numeric ID for import, got %q. Error: %s", req.ID, err.Error()),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(
		ctx,
		path.Root("id"),
		numericID,
	)...)
}
