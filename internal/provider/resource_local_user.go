// internal/provider/resource_local_user.go
package provider

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-clearpass/internal/client" // Unser SDK (Box 3)

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider-defined types implement framework interfaces.
var _ resource.Resource = &localUserResource{}

// localUserResource defines the resource implementation.
type localUserResource struct {
	client client.ClientInterface // Our API client (Box 3)
}

// localUserResourceModel defines the HCL data model for the resource.
// This is our "translator" struct between HCL and the Go client.
type localUserResourceModel struct {
	ID                 types.Int64  `tfsdk:"id"` // We will use the 'user_id' string as the TF ID
	UserID             types.String `tfsdk:"user_id"`
	Username           types.String `tfsdk:"username"`
	Password           types.String `tfsdk:"password"`
	RoleName           types.String `tfsdk:"role_name"`
	Enabled            types.Bool   `tfsdk:"enabled"`
	PasswordHash       types.String `tfsdk:"password_hash"`
	PasswordNTLMHash   types.String `tfsdk:"password_ntlm_hash"`
	ChangePwdNextLogin types.Bool   `tfsdk:"change_pwd_next_login"`
	Attributes         types.Map    `tfsdk:"attributes"`
}

// NewLocalUserResource is a factory function for the localUserResource.
func NewLocalUserResource() resource.Resource {
	return &localUserResource{}
}

// Metadata returns the resource type name.
func (r *localUserResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_local_user" // e.g., "clearpass_local_user"
}

// Schema defines the HCL attributes for the resource.
func (r *localUserResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a local user in ClearPass.",

		Attributes: map[string]schema.Attribute{
			// We use 'user_id' as the main ID for this resource.
			// "id" is a special Terraform attribute.
			"id": schema.Int64Attribute{
				Description: "The numeric ID of the local user. This is used as the Terraform ID.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"user_id": schema.StringAttribute{
				Description: "The unique user ID (e.g., 'tf-test-user').",
				Required:    true,
			},
			"username": schema.StringAttribute{
				Description: "The username (often the same as user_id).",
				Required:    true,
			},
			"password": schema.StringAttribute{
				Description: "The user's password.",
				Required:    true,
				Sensitive:   true, // Marks this as sensitive in TF state/logs
			},
			"role_name": schema.StringAttribute{
				Description: "The name of the role to assign to the user (e.g., '[Employee]').",
				Required:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the user account is enabled. Defaults to 'true' if not specified.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"password_hash": schema.StringAttribute{
				Description: "The password hash of the local user.",
				Optional:    true,
				Sensitive:   true,
			},
			"password_ntlm_hash": schema.StringAttribute{
				Description: "The NTLM password hash of the local user.",
				Optional:    true,
				Sensitive:   true,
			},
			"change_pwd_next_login": schema.BoolAttribute{
				Description: "Flag indicating if the password change is required in next login.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"attributes": schema.MapAttribute{
				Description: "Additional attributes (key/value pairs) may be stored with the local user account.",
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure is called by the provider 'factory' to pass us the API client.
func (r *localUserResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
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

// Create is called when the resource is created (terraform apply).
func (r *localUserResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan localUserResourceModel // This holds the HCL data from the user's .tf file

	// Read Terraform plan data into the 'plan' model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// === TRANSLATION 1: HCL Model -> API Client Model ===
	apiPayload := &client.LocalUserCreate{
		UserID:   plan.UserID.ValueString(),
		Username: plan.Username.ValueString(),
		Password: plan.Password.ValueString(),
		RoleName: plan.RoleName.ValueString(),
	}

	if !plan.PasswordHash.IsNull() {
		apiPayload.PasswordHash = plan.PasswordHash.ValueString()
	}
	if !plan.PasswordNTLMHash.IsNull() {
		apiPayload.PasswordNTLMHash = plan.PasswordNTLMHash.ValueString()
	}
	if !plan.ChangePwdNextLogin.IsNull() {
		val := plan.ChangePwdNextLogin.ValueBool()
		apiPayload.ChangePwdNextLogin = &val
	}
	if !plan.Attributes.IsNull() {
		attrs := make(map[string]string)
		diag := plan.Attributes.ElementsAs(ctx, &attrs, false)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		apiPayload.Attributes = attrs
	}

	// Handle optional 'enabled' field
	if !plan.Enabled.IsNull() {
		enabledVal := plan.Enabled.ValueBool()
		apiPayload.Enabled = &enabledVal
	}

	// === API CALL ===
	// Use our client (Box 3) to create the user
	createdUser, err := r.client.CreateLocalUser(ctx, apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to create local user: %s", err))
		return
	}

	// === TRANSLATION 2: API Client Result -> HCL State ===
	// The API response ('createdUser') is the source of truth.
	// We save its data back into our 'plan' model to set the state.
	plan.ID = types.Int64Value(int64(createdUser.ID)) // Use UserID as the TF ID
	plan.UserID = types.StringValue(createdUser.UserID)
	plan.Username = types.StringValue(createdUser.Username)
	plan.RoleName = types.StringValue(createdUser.RoleName)
	plan.Enabled = types.BoolValue(createdUser.Enabled)
	plan.ChangePwdNextLogin = types.BoolValue(createdUser.ChangePwdNextLogin)

	if len(createdUser.Attributes) > 0 {
		attrs, diag := types.MapValueFrom(ctx, types.StringType, createdUser.Attributes)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.Attributes = attrs
	} else {
		plan.Attributes = types.MapNull(types.StringType)
	}
	// We do NOT save the password back from the API (it's write-only)
	// We also don't get hashes back in the result usually, but if we did we would map them.
	// For now, we keep the plan values for hashes if they were set, to avoid drift if API doesn't return them.
	// In a real scenario, we might need to handle this differently if the API returns hashes.
	// For now, we just rely on state preservation for unknown values if they are not in the response.

	// Save data to Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *localUserResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state localUserResourceModel

	// Read Terraform state data into the 'state' model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the numeric ID from the state
	numericID := state.ID.ValueInt64()

	// === API CALL ===
	// Call our new GetLocalUser function
	user, err := r.client.GetLocalUser(ctx, int(numericID))
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to read local user: %s", err))
		return
	}

	// === 404 Not Found Handling ===
	if user == nil {
		// The resource was deleted outside of Terraform.
		// Tell Terraform to "forget" this resource.
		resp.Diagnostics.AddWarning("Resource Not Found", "Local user not found, removing from state.")
		resp.State.RemoveResource(ctx) // This is the key
		return
	}

	// === TRANSLATION: API Result -> HCL State ===
	// Refresh the state with the latest data from the API
	state.ID = types.Int64Value(int64(user.ID))
	state.UserID = types.StringValue(user.UserID)
	state.Username = types.StringValue(user.Username)
	state.RoleName = types.StringValue(user.RoleName)
	state.Enabled = types.BoolValue(user.Enabled)
	state.ChangePwdNextLogin = types.BoolValue(user.ChangePwdNextLogin)

	if len(user.Attributes) > 0 {
		attrs, diag := types.MapValueFrom(ctx, types.StringType, user.Attributes)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Attributes = attrs
	} else {
		state.Attributes = types.MapNull(types.StringType)
	}
	// We don't read the password, as it's write-only

	// Save refreshed data to Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is called when the resource is updated.
func (r *localUserResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan localUserResourceModel

	// Read Terraform plan data into the 'plan' model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// === TRANSLATION 1: HCL Plan -> API Client Model ===
	apiPayload := &client.LocalUserUpdate{}

	if !plan.UserID.IsUnknown() {
		apiPayload.UserID = plan.UserID.ValueString()
	}
	if !plan.Username.IsUnknown() {
		apiPayload.Username = plan.Username.ValueString()
	}
	if !plan.Password.IsUnknown() {
		apiPayload.Password = plan.Password.ValueString()
	}
	if !plan.RoleName.IsUnknown() {
		apiPayload.RoleName = plan.RoleName.ValueString()
	}
	if !plan.PasswordHash.IsUnknown() {
		apiPayload.PasswordHash = plan.PasswordHash.ValueString()
	}
	if !plan.PasswordNTLMHash.IsUnknown() {
		apiPayload.PasswordNTLMHash = plan.PasswordNTLMHash.ValueString()
	}
	if !plan.ChangePwdNextLogin.IsUnknown() {
		val := plan.ChangePwdNextLogin.ValueBool()
		apiPayload.ChangePwdNextLogin = &val
	}
	if !plan.Attributes.IsUnknown() {
		attrs := make(map[string]string)
		diag := plan.Attributes.ElementsAs(ctx, &attrs, false)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		apiPayload.Attributes = attrs
	}
	if !plan.Enabled.IsUnknown() {
		enabledVal := plan.Enabled.ValueBool()
		apiPayload.Enabled = &enabledVal
	}

	// Get the numeric ID from the plan (or state, it's the same)
	numericID := plan.ID.ValueInt64()

	// === API CALL ===
	updatedUser, err := r.client.UpdateLocalUser(ctx, int(numericID), apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to update local user: %s", err))
		return
	}

	// === TRANSLATION 2: API Result -> HCL State ===
	// Refresh the state with the data returned from the API
	plan.ID = types.Int64Value(int64(updatedUser.ID))
	plan.UserID = types.StringValue(updatedUser.UserID)
	plan.Username = types.StringValue(updatedUser.Username)
	plan.RoleName = types.StringValue(updatedUser.RoleName)
	plan.Enabled = types.BoolValue(updatedUser.Enabled)
	plan.ChangePwdNextLogin = types.BoolValue(updatedUser.ChangePwdNextLogin)

	if len(updatedUser.Attributes) > 0 {
		attrs, diag := types.MapValueFrom(ctx, types.StringType, updatedUser.Attributes)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.Attributes = attrs
	} else {
		plan.Attributes = types.MapNull(types.StringType)
	}

	// Save updated data to Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete is called when the resource is destroyed (terraform destroy).
func (r *localUserResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state localUserResourceModel

	// Read Terraform state data into the 'state' model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	numericID := state.ID.ValueInt64() // Holt die numerische ID aus dem State

	// === API CALL ===
	err := r.client.DeleteLocalUser(ctx, int(numericID)) // int64 zu int konvertieren
	if err != nil {
		resp.Diagnostics.AddError("ClearPass API Error", fmt.Sprintf("Failed to delete local user with ID %d: %s", numericID, err))
		return
	}
}

// ImportState is used to retrieve data from the API and populate the state.
func (r *localUserResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) { // We expect the ID to be the numeric ID of the user.
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
