package provider

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &enforcementProfileResource{}

type enforcementProfileResource struct {
	client client.ClientInterface
}

type enforcementProfileModel struct {
	ID                     types.Int64  `tfsdk:"id"`
	Name                   types.String `tfsdk:"name"`
	Description            types.String `tfsdk:"description"`
	Type                   types.String `tfsdk:"type"`
	Action                 types.String `tfsdk:"action"`
	DeviceGroupList        types.List   `tfsdk:"device_group_list"` // List of strings
	AgentTemplate          types.String `tfsdk:"agent_template"`
	PostAuthTemplate       types.String `tfsdk:"post_auth_template"`
	RadiusDynAuthzTemplate types.String `tfsdk:"radius_dyn_authz_template"`
	Attributes             types.List   `tfsdk:"attributes"` // List of profileAttributeModel
}

type profileAttributeModel struct {
	Type  types.String `tfsdk:"type"`
	Name  types.String `tfsdk:"name"`
	Value types.String `tfsdk:"value"`
}

func NewEnforcementProfileResource() resource.Resource {
	return &enforcementProfileResource{}
}

func (r *enforcementProfileResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_enforcement_profile"
}

func (r *enforcementProfileResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an Enforcement Profile.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description:   "Numeric ID of the profile.",
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Description: "Name of the profile.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description:   "Description of the profile.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"type": schema.StringAttribute{
				Description: "Type (e.g. RADIUS, TACACS, Agent).",
				Required:    true,
			},
			"action": schema.StringAttribute{
				Description: "Action (Accept, Reject, Drop). Mostly used for RADIUS.",
				Optional:    true,
			},
			"device_group_list": schema.ListAttribute{
				Description: "Device Group List.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"agent_template": schema.StringAttribute{
				Description: "Agent Enforcement Profile Template (Agent, AgentScript).",
				Optional:    true,
			},
			"post_auth_template": schema.StringAttribute{
				Description: "Post Authentication Enforcement Profile Template (EntityUpdate, SessionRestriction, SessionNotify).",
				Optional:    true,
			},
			"radius_dyn_authz_template": schema.StringAttribute{
				Description: "RADIUS Dynamic Authorization Template.",
				Optional:    true,
			},
			"attributes": schema.ListNestedAttribute{
				Description: "List of attributes (Dictionary/Name/Value pairs).",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							Description: "Type of attribute (e.g. 'Radius:IETF').",
							Required:    true,
						},
						"name": schema.StringAttribute{
							Description: "Name of attribute (e.g. 'Filter-Id').",
							Required:    true,
						},
						"value": schema.StringAttribute{
							Description: "Value of attribute.",
							Required:    true,
						},
					},
				},
			},
		},
	}
}

func (r *enforcementProfileResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Type", fmt.Sprintf("Expected ClientInterface, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

func (r *enforcementProfileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan enforcementProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPayload := &client.EnforcementProfileCreate{
		Name:       plan.Name.ValueString(),
		Type:       plan.Type.ValueString(),
		Attributes: expandProfileAttributes(ctx, plan.Attributes, &resp.Diagnostics),
	}
	if !plan.Description.IsNull() {
		apiPayload.Description = plan.Description.ValueString()
	}
	if !plan.Action.IsNull() {
		apiPayload.Action = plan.Action.ValueString()
	}
	if !plan.AgentTemplate.IsNull() {
		apiPayload.AgentTemplate = plan.AgentTemplate.ValueString()
	}
	if !plan.PostAuthTemplate.IsNull() {
		apiPayload.PostAuthTemplate = plan.PostAuthTemplate.ValueString()
	}
	if !plan.RadiusDynAuthzTemplate.IsNull() {
		apiPayload.RadiusDynAuthzTemplate = plan.RadiusDynAuthzTemplate.ValueString()
	}
	if !plan.DeviceGroupList.IsNull() {
		var deviceGroups []string
		resp.Diagnostics.Append(plan.DeviceGroupList.ElementsAs(ctx, &deviceGroups, false)...)
		apiPayload.DeviceGroupList = deviceGroups
	}
	if resp.Diagnostics.HasError() {
		return
	}

	created, err := r.client.CreateEnforcementProfile(ctx, apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
		return
	}

	// Map back to state
	plan.ID = types.Int64Value(int64(created.ID))
	plan.Name = types.StringValue(created.Name)
	plan.Description = types.StringValue(created.Description)
	plan.Type = types.StringValue(created.Type)
	plan.Action = types.StringValue(created.Action)
	if created.AgentTemplate != "" {
		plan.AgentTemplate = types.StringValue(created.AgentTemplate)
	} else {
		plan.AgentTemplate = types.StringNull()
	}
	if created.PostAuthTemplate != "" {
		plan.PostAuthTemplate = types.StringValue(created.PostAuthTemplate)
	} else {
		plan.PostAuthTemplate = types.StringNull()
	}
	if created.RadiusDynAuthzTemplate != "" {
		plan.RadiusDynAuthzTemplate = types.StringValue(created.RadiusDynAuthzTemplate)
	} else {
		plan.RadiusDynAuthzTemplate = types.StringNull()
	}

	if created.DeviceGroupList != nil {
		deviceGroupsList, diags := types.ListValueFrom(ctx, types.StringType, created.DeviceGroupList)
		resp.Diagnostics.Append(diags...)
		plan.DeviceGroupList = deviceGroupsList
	} else {
		plan.DeviceGroupList = types.ListNull(types.StringType)
	}

	var diags diag.Diagnostics
	plan.Attributes, diags = flattenProfileAttributes(ctx, created.Attributes)
	resp.Diagnostics.Append(diags...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *enforcementProfileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state enforcementProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	profile, err := r.client.GetEnforcementProfile(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
		return
	}
	if profile == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.Name = types.StringValue(profile.Name)
	state.Description = types.StringValue(profile.Description)
	state.Type = types.StringValue(profile.Type)
	state.Action = types.StringValue(profile.Action)
	if profile.AgentTemplate != "" {
		state.AgentTemplate = types.StringValue(profile.AgentTemplate)
	} else {
		state.AgentTemplate = types.StringNull()
	}
	if profile.PostAuthTemplate != "" {
		state.PostAuthTemplate = types.StringValue(profile.PostAuthTemplate)
	} else {
		state.PostAuthTemplate = types.StringNull()
	}
	if profile.RadiusDynAuthzTemplate != "" {
		state.RadiusDynAuthzTemplate = types.StringValue(profile.RadiusDynAuthzTemplate)
	} else {
		state.RadiusDynAuthzTemplate = types.StringNull()
	}

	if profile.DeviceGroupList != nil {
		deviceGroupsList, diags := types.ListValueFrom(ctx, types.StringType, profile.DeviceGroupList)
		resp.Diagnostics.Append(diags...)
		state.DeviceGroupList = deviceGroupsList
	} else {
		state.DeviceGroupList = types.ListNull(types.StringType)
	}

	var diags diag.Diagnostics
	state.Attributes, diags = flattenProfileAttributes(ctx, profile.Attributes)
	resp.Diagnostics.Append(diags...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *enforcementProfileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan enforcementProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPayload := &client.EnforcementProfileUpdate{
		Attributes: expandProfileAttributes(ctx, plan.Attributes, &resp.Diagnostics),
	}
	if !plan.Name.IsUnknown() {
		apiPayload.Name = plan.Name.ValueString()
	}
	if !plan.Description.IsUnknown() {
		apiPayload.Description = plan.Description.ValueString()
	}
	if !plan.Type.IsUnknown() {
		apiPayload.Type = plan.Type.ValueString()
	}
	if !plan.Action.IsUnknown() {
		apiPayload.Action = plan.Action.ValueString()
	}
	if !plan.AgentTemplate.IsUnknown() {
		apiPayload.AgentTemplate = plan.AgentTemplate.ValueString()
	}
	if !plan.PostAuthTemplate.IsUnknown() {
		apiPayload.PostAuthTemplate = plan.PostAuthTemplate.ValueString()
	}
	if !plan.RadiusDynAuthzTemplate.IsUnknown() {
		apiPayload.RadiusDynAuthzTemplate = plan.RadiusDynAuthzTemplate.ValueString()
	}
	if !plan.DeviceGroupList.IsNull() && !plan.DeviceGroupList.IsUnknown() {
		var deviceGroups []string
		resp.Diagnostics.Append(plan.DeviceGroupList.ElementsAs(ctx, &deviceGroups, false)...)
		apiPayload.DeviceGroupList = deviceGroups
	}

	if resp.Diagnostics.HasError() {
		return
	}

	updated, err := r.client.UpdateEnforcementProfile(ctx, int(plan.ID.ValueInt64()), apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
		return
	}

	plan.Name = types.StringValue(updated.Name)
	plan.Description = types.StringValue(updated.Description)
	plan.Type = types.StringValue(updated.Type)
	plan.Action = types.StringValue(updated.Action)

	var diags diag.Diagnostics
	plan.Attributes, diags = flattenProfileAttributes(ctx, updated.Attributes)
	resp.Diagnostics.Append(diags...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *enforcementProfileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state enforcementProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.DeleteEnforcementProfile(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
	}
}

// --- Helpers ---

func expandProfileAttributes(ctx context.Context, list types.List, diags *diag.Diagnostics) []*client.ProfileAttribute {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var tfAttrs []profileAttributeModel
	diags.Append(list.ElementsAs(ctx, &tfAttrs, false)...)
	if diags.HasError() {
		return nil
	}
	var apiAttrs []*client.ProfileAttribute
	for _, item := range tfAttrs {
		apiAttrs = append(apiAttrs, &client.ProfileAttribute{
			Type:  item.Type.ValueString(),
			Name:  item.Name.ValueString(),
			Value: item.Value.ValueString(),
		})
	}
	return apiAttrs
}

func flattenProfileAttributes(ctx context.Context, apiAttrs []*client.ProfileAttribute) (types.List, diag.Diagnostics) {
	if len(apiAttrs) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: profileAttributeModel{}.attrTypes()}), nil
	}
	var tfAttrs []profileAttributeModel
	for _, item := range apiAttrs {
		tfAttrs = append(tfAttrs, profileAttributeModel{
			Type:  types.StringValue(item.Type),
			Name:  types.StringValue(item.Name),
			Value: types.StringValue(item.Value),
		})
	}
	return types.ListValueFrom(ctx, types.ObjectType{AttrTypes: profileAttributeModel{}.attrTypes()}, tfAttrs)
}

func (m profileAttributeModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type":  types.StringType,
		"name":  types.StringType,
		"value": types.StringType,
	}
}

// ImportState is used to retrieve data from the API and populate the state.
func (r *enforcementProfileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// We expect the ID to be the numeric ID of the user.
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
