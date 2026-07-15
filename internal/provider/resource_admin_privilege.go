package provider

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider-defined types implement framework interfaces.
var _ resource.Resource = &adminPrivilegeResource{}
var _ resource.ResourceWithConfigure = &adminPrivilegeResource{}
var _ resource.ResourceWithImportState = &adminPrivilegeResource{}

// adminPrivilegeResource defines the resource implementation.
type adminPrivilegeResource struct {
	client client.ClientInterface
}

// adminPrivilegeResourceModel defines the HCL data model for the resource.
type adminPrivilegeResourceModel struct {
	ID                   types.Int64  `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	Description          types.String `tfsdk:"description"`
	AccessType           types.String `tfsdk:"access_type"`
	CppmPrivileges       types.Map    `tfsdk:"cppm_privileges"`
	InsightPrivileges    types.Map    `tfsdk:"insight_privileges"`
	AllowPasswords       types.Bool   `tfsdk:"allow_passwords"`
	AllowSecurityConfigs types.Bool   `tfsdk:"allow_security_configs"`
}

// NewAdminPrivilegeResource is a factory function for the adminPrivilegeResource.
func NewAdminPrivilegeResource() resource.Resource {
	return &adminPrivilegeResource{}
}

// Metadata returns the resource type name.
func (r *adminPrivilegeResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_admin_privilege"
}

// Schema defines the HCL attributes for the resource.
func (r *adminPrivilegeResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages ClearPass administrative privileges. Admin privileges define access levels to various ClearPass Policy Manager and Insight modules.",

		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Numeric ID of the admin privilege assigned by ClearPass. Used as the Terraform resource ID.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Unique name of the admin privilege.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the admin privilege.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"access_type": schema.StringAttribute{
				Description: "Property to decide the access type of the user (UI, API, FULL).",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("UI", "API", "FULL"),
				},
			},
			"cppm_privileges": schema.MapAttribute{
				Description: "Privilege list for ClearPass Policy Manager in JSON object format (e.g., {'con:RWD': 'RW', 'mon': 'R'}).",
				Required:    true,
				ElementType: types.StringType,
			},
			"insight_privileges": schema.MapAttribute{
				Description: "Privilege list for ClearPass Insight in JSON object format (e.g., {'report': 'RWD', 'dashboard': 'RW'}).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"allow_passwords": schema.BoolAttribute{
				Description: "If selected, all passwords may be displayed in the response.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"allow_security_configs": schema.BoolAttribute{
				Description: "If selected, Admin user will have access to security configuration.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure passes the API client to the resource.
func (r *adminPrivilegeResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *adminPrivilegeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan adminPrivilegeResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPayload := &client.AdminPrivilegeCreate{
		Name: plan.Name.ValueString(),
	}

	if !plan.Description.IsNull() {
		apiPayload.Description = plan.Description.ValueString()
	}
	if !plan.AccessType.IsNull() {
		apiPayload.AccessType = plan.AccessType.ValueString()
	}

	if !plan.CppmPrivileges.IsNull() {
		cppm := make(map[string]string)
		diag := plan.CppmPrivileges.ElementsAs(ctx, &cppm, false)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		apiPayload.CppmPrivileges = cppm
	}

	if !plan.InsightPrivileges.IsNull() {
		insight := make(map[string]string)
		diag := plan.InsightPrivileges.ElementsAs(ctx, &insight, false)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		apiPayload.InsightPrivileges = insight
	}

	if !plan.AllowPasswords.IsNull() {
		val := plan.AllowPasswords.ValueBool()
		apiPayload.AllowPasswords = &val
	}

	if !plan.AllowSecurityConfigs.IsNull() {
		val := plan.AllowSecurityConfigs.ValueBool()
		apiPayload.AllowSecurityConfigs = &val
	}

	created, err := r.client.CreateAdminPrivilege(ctx, apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to create admin privilege: %s", err))
		return
	}

	// Save API response back to state
	plan.ID = types.Int64Value(int64(created.ID))
	plan.Name = types.StringValue(created.Name)
	plan.Description = types.StringValue(created.Description)
	plan.AccessType = types.StringValue(created.AccessType)
	plan.AllowPasswords = types.BoolValue(created.AllowPasswords)
	plan.AllowSecurityConfigs = types.BoolValue(created.AllowSecurityConfigs)

	if len(created.CppmPrivileges) > 0 {
		cppm, diag := types.MapValueFrom(ctx, types.StringType, created.CppmPrivileges)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.CppmPrivileges = cppm
	} else {
		plan.CppmPrivileges = types.MapNull(types.StringType)
	}

	if len(created.InsightPrivileges) > 0 {
		insight, diag := types.MapValueFrom(ctx, types.StringType, created.InsightPrivileges)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.InsightPrivileges = insight
	} else {
		plan.InsightPrivileges = types.MapNull(types.StringType)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read is called to refresh the resource state.
func (r *adminPrivilegeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state adminPrivilegeResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	numericID := state.ID.ValueInt64()
	privilege, err := r.client.GetAdminPrivilege(ctx, int(numericID))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to read admin privilege: %s", err))
		return
	}

	if privilege == nil {
		resp.Diagnostics.AddWarning("Resource Not Found", "Admin privilege not found, removing from state.")
		resp.State.RemoveResource(ctx)
		return
	}

	// Refresh state with data from API
	state.ID = types.Int64Value(int64(privilege.ID))
	state.Name = types.StringValue(privilege.Name)
	state.Description = types.StringValue(privilege.Description)
	state.AccessType = types.StringValue(privilege.AccessType)
	state.AllowPasswords = types.BoolValue(privilege.AllowPasswords)
	state.AllowSecurityConfigs = types.BoolValue(privilege.AllowSecurityConfigs)

	if len(privilege.CppmPrivileges) > 0 {
		cppm, diag := types.MapValueFrom(ctx, types.StringType, privilege.CppmPrivileges)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.CppmPrivileges = cppm
	} else {
		state.CppmPrivileges = types.MapNull(types.StringType)
	}

	if len(privilege.InsightPrivileges) > 0 {
		insight, diag := types.MapValueFrom(ctx, types.StringType, privilege.InsightPrivileges)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.InsightPrivileges = insight
	} else {
		state.InsightPrivileges = types.MapNull(types.StringType)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is called when the resource is updated.
func (r *adminPrivilegeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan adminPrivilegeResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPayload := &client.AdminPrivilegeUpdate{}

	if !plan.Name.IsUnknown() {
		apiPayload.Name = plan.Name.ValueString()
	}
	if !plan.Description.IsUnknown() {
		apiPayload.Description = plan.Description.ValueString()
	}
	if !plan.AccessType.IsUnknown() {
		apiPayload.AccessType = plan.AccessType.ValueString()
	}

	if !plan.CppmPrivileges.IsNull() && !plan.CppmPrivileges.IsUnknown() {
		cppm := make(map[string]string)
		diag := plan.CppmPrivileges.ElementsAs(ctx, &cppm, false)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		apiPayload.CppmPrivileges = cppm
	}

	if !plan.InsightPrivileges.IsNull() && !plan.InsightPrivileges.IsUnknown() {
		insight := make(map[string]string)
		diag := plan.InsightPrivileges.ElementsAs(ctx, &insight, false)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		apiPayload.InsightPrivileges = insight
	}

	if !plan.AllowPasswords.IsUnknown() {
		val := plan.AllowPasswords.ValueBool()
		apiPayload.AllowPasswords = &val
	}

	if !plan.AllowSecurityConfigs.IsUnknown() {
		val := plan.AllowSecurityConfigs.ValueBool()
		apiPayload.AllowSecurityConfigs = &val
	}

	numericID := plan.ID.ValueInt64()
	updated, err := r.client.UpdateAdminPrivilege(ctx, int(numericID), apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to update admin privilege: %s", err))
		return
	}

	// Save updated data to state
	plan.ID = types.Int64Value(int64(updated.ID))
	plan.Name = types.StringValue(updated.Name)
	plan.Description = types.StringValue(updated.Description)
	plan.AccessType = types.StringValue(updated.AccessType)
	plan.AllowPasswords = types.BoolValue(updated.AllowPasswords)
	plan.AllowSecurityConfigs = types.BoolValue(updated.AllowSecurityConfigs)

	if len(updated.CppmPrivileges) > 0 {
		cppm, diag := types.MapValueFrom(ctx, types.StringType, updated.CppmPrivileges)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.CppmPrivileges = cppm
	} else {
		plan.CppmPrivileges = types.MapNull(types.StringType)
	}

	if len(updated.InsightPrivileges) > 0 {
		insight, diag := types.MapValueFrom(ctx, types.StringType, updated.InsightPrivileges)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.InsightPrivileges = insight
	} else {
		plan.InsightPrivileges = types.MapNull(types.StringType)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete is called when the resource is destroyed.
func (r *adminPrivilegeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state adminPrivilegeResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	numericID := state.ID.ValueInt64()
	err := r.client.DeleteAdminPrivilege(ctx, int(numericID))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to delete admin privilege with ID %d: %s", numericID, err))
		return
	}
}

// ImportState is called to import an existing resource.
func (r *adminPrivilegeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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
