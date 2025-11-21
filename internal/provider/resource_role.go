// internal/provider/resource_role.go
package provider

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider-defined types implement framework interfaces
var _ resource.Resource = &roleResource{}

// roleResource defines the resource implementation.
type roleResource struct {
	client client.ClientInterface
}

// roleResourceModel defines the HCL data model for the resource.
type roleResourceModel struct {
	ID          types.Int64  `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
}

// NewRoleResource is a factory function for the roleResource.
func NewRoleResource() resource.Resource {
	return &roleResource{}
}

// Metadata returns the resource type name.
func (r *roleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

// Schema defines the HCL attributes for the resource.
func (r *roleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a user role in ClearPass. Roles define access levels and permissions for authenticated users. " +
			"Common roles include [Employee] for full access, Guest for limited access, and custom roles for specific requirements. " +
			"Roles are referenced by enforcement policies and role mapping rules.",

		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Numeric ID of the role assigned by ClearPass. Used as the Terraform resource ID.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Unique name of the role (e.g., 'Guest', '[Employee]', '[Contractor]'). System roles typically use square brackets.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Human-readable description explaining the role's purpose and intended use.",
				Optional:    true,
				Computed:    true, // Proactively prevent "inconsistent result"
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure passes the API client to the resource.
func (r *roleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPayload := &client.RoleCreate{
		Name: plan.Name.ValueString(),
	}
	if !plan.Description.IsNull() {
		apiPayload.Description = plan.Description.ValueString()
	}

	createdRole, err := r.client.CreateRole(ctx, apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to create role: %s", err))
		return
	}

	// Save API response back to state
	plan.ID = types.Int64Value(int64(createdRole.ID))
	plan.Name = types.StringValue(createdRole.Name)
	plan.Description = types.StringValue(createdRole.Description)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read is called to refresh the resource state.
func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	numericID := state.ID.ValueInt64()
	role, err := r.client.GetRole(ctx, int(numericID))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to read role: %s", err))
		return
	}

	if role == nil {
		// Role was deleted outside of Terraform
		resp.Diagnostics.AddWarning("Resource Not Found", "Role not found, removing from state.")
		resp.State.RemoveResource(ctx)
		return
	}

	// Refresh state with data from API
	state.ID = types.Int64Value(int64(role.ID))
	state.Name = types.StringValue(role.Name)
	state.Description = types.StringValue(role.Description)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is called when the resource is updated.
func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan roleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPayload := &client.RoleUpdate{}
	if !plan.Name.IsUnknown() {
		apiPayload.Name = plan.Name.ValueString()
	}
	if !plan.Description.IsUnknown() {
		apiPayload.Description = plan.Description.ValueString()
	}

	numericID := plan.ID.ValueInt64()
	updatedRole, err := r.client.UpdateRole(ctx, int(numericID), apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to update role: %s", err))
		return
	}

	// Save updated data to state
	plan.ID = types.Int64Value(int64(updatedRole.ID))
	plan.Name = types.StringValue(updatedRole.Name)
	plan.Description = types.StringValue(updatedRole.Description)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete is called when the resource is destroyed.
func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	numericID := state.ID.ValueInt64()
	err := r.client.DeleteRole(ctx, int(numericID))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to delete role with ID %d: %s", numericID, err))
		return
	}
}

func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	numericID, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected a numeric ID for import, got %q. Error: %s", req.ID, err.Error()),
		)
		return
	}

	// The framework requires us to set the 'id' field in the state.
	// The subsequent Read function will use this ID to fetch the full state.
	resp.Diagnostics.Append(resp.State.SetAttribute(
		ctx,
		path.Root("id"),
		numericID,
	)...)
}
