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
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
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
	Attributes             types.List   `tfsdk:"attributes"`           // List of profileAttributeModel
	TacacsServiceParams    types.Object `tfsdk:"tacacs_service_param"` // type tacacsServiceParamModel
}

type tacacsServiceParamModel struct {
	PrivilegeLevel           types.Int64  `tfsdk:"privilege_level"`
	Services                 types.List   `tfsdk:"services"`
	AuthorizeAttributeStatus types.String `tfsdk:"authorize_attribute_status"`
	TacacsCommandConfig      types.Object `tfsdk:"tacacs_command_config"` // type tacacsCommandConfigModel
}

type tacacsCommandConfigModel struct {
	ServiceType         types.String `tfsdk:"service_type"`
	PermitUnmatchedCmds types.Bool   `tfsdk:"permit_unmatched_cmds"`
	Commands            types.List   `tfsdk:"commands"` // List of tacacsCommandModel
}

type tacacsCommandModel struct {
	Command             types.String `tfsdk:"command"`
	PermitUnmatchedArgs types.Bool   `tfsdk:"permit_unmatched_args"`
	CommandArgs         types.List   `tfsdk:"command_args"` // List of tacacsCommandArgsModel
}

type tacacsCommandArgsModel struct {
	Argument     types.String `tfsdk:"argument"`
	PermitAction types.Bool   `tfsdk:"permit_action"`
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
		Description: "Manages an Enforcement Profile. Enforcement profiles define the actions to be taken when a policy rule is matched, " +
			"such as returning RADIUS attributes or redirecting a user.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description:   "Numeric ID of the profile.",
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Description: "The name of the enforcement profile.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description:   "Description of the enforcement profile.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"type": schema.StringAttribute{
				Description: "The type of enforcement profile (e.g., 'RADIUS', 'TACACS', 'Agent').",
				Required:    true,
			},
			"action": schema.StringAttribute{
				Description: "The action to take (e.g., 'Accept', 'Reject', 'Drop'). Primarily used for RADIUS profiles.",
				Optional:    true,
			},
			"device_group_list": schema.ListAttribute{
				Description: "A list of device groups associated with this profile.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"agent_template": schema.StringAttribute{
				Description: "Template for Agent enforcement profiles (e.g., 'Agent', 'AgentScript').",
				Optional:    true,
			},
			"post_auth_template": schema.StringAttribute{
				Description: "Template for Post-Authentication enforcement profiles (e.g., 'EntityUpdate', 'SessionRestriction').",
				Optional:    true,
			},
			"radius_dyn_authz_template": schema.StringAttribute{
				Description: "Template for RADIUS Dynamic Authorization.",
				Optional:    true,
			},
			"attributes": schema.ListNestedAttribute{
				Description: "A list of attributes to return or apply.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							Description: "The type of attribute (e.g., 'Radius:IETF', 'Radius:Cisco').",
							Required:    true,
						},
						"name": schema.StringAttribute{
							Description: "The name of the attribute (e.g., 'Filter-Id', 'Tunnel-Type').",
							Required:    true,
						},
						"value": schema.StringAttribute{
							Description: "The value of the attribute.",
							Required:    true,
						},
					},
				},
			},
			"tacacs_service_param": schema.SingleNestedAttribute{
				Description: "TACACS+ Service Parameters.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"privilege_level": schema.Int64Attribute{
						Description: "Privilege Level <0-15>.",
						Optional:    true,
					},
					"services": schema.ListAttribute{
						Description: "Selected Services.",
						Optional:    true,
						ElementType: types.StringType,
					},
					"authorize_attribute_status": schema.StringAttribute{
						Description: "Authorize Attribute Status (ADD, REPLACE, FAIL).",
						Optional:    true,
					},
					"tacacs_command_config": schema.SingleNestedAttribute{
						Description: "Commands Configuration.",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"service_type": schema.StringAttribute{
								Description: "Service Type (Shell, PIX Shell).",
								Optional:    true,
							},
							"permit_unmatched_cmds": schema.BoolAttribute{
								Description: "Enable to permit unmatched commands.",
								Optional:    true,
							},
							"commands": schema.ListNestedAttribute{
								Description: "Specify which commands with arguments are permitted/denied.",
								Optional:    true,
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"command": schema.StringAttribute{
											Description: "Shell Command.",
											Optional:    true,
										},
										"permit_unmatched_args": schema.BoolAttribute{
											Description: "Enable to permit unmatched arguments.",
											Optional:    true,
										},
										"command_args": schema.ListNestedAttribute{
											Description: "List of Command Arguments.",
											Optional:    true,
											NestedObject: schema.NestedAttributeObject{
												Attributes: map[string]schema.Attribute{
													"argument": schema.StringAttribute{
														Description: "Command Argument.",
														Optional:    true,
													},
													"permit_action": schema.BoolAttribute{
														Description: "Enable to permit unmatched action.",
														Optional:    true,
													},
												},
											},
										},
									},
								},
							},
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
	desiredTacacsServiceParams := plan.TacacsServiceParams

	apiPayload := &client.EnforcementProfileCreate{
		Name:                plan.Name.ValueString(),
		Type:                plan.Type.ValueString(),
		Attributes:          expandProfileAttributes(ctx, plan.Attributes, &resp.Diagnostics),
		TacacsServiceParams: expandTacacsServiceParams(ctx, plan.TacacsServiceParams, &resp.Diagnostics),
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

	plan.TacacsServiceParams, diags = flattenTacacsServiceParams(ctx, created.TacacsServiceParams)
	resp.Diagnostics.Append(diags...)
	preserveNullTacacsCommands(ctx, desiredTacacsServiceParams, &plan.TacacsServiceParams, &resp.Diagnostics)

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

	state.TacacsServiceParams, diags = flattenTacacsServiceParams(ctx, profile.TacacsServiceParams)
	resp.Diagnostics.Append(diags...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *enforcementProfileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan enforcementProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior enforcementProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	desiredTacacsServiceParams := plan.TacacsServiceParams

	apiPayload := &client.EnforcementProfileUpdate{
		Attributes:          expandProfileAttributes(ctx, plan.Attributes, &resp.Diagnostics),
		TacacsServiceParams: expandTacacsServiceParams(ctx, plan.TacacsServiceParams, &resp.Diagnostics),
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

	plan.TacacsServiceParams, diags = flattenTacacsServiceParams(ctx, updated.TacacsServiceParams)
	resp.Diagnostics.Append(diags...)
	if shouldPreserveNullTacacsCommands(ctx, prior.TacacsServiceParams, desiredTacacsServiceParams, &resp.Diagnostics) {
		preserveNullTacacsCommands(ctx, desiredTacacsServiceParams, &plan.TacacsServiceParams, &resp.Diagnostics)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func shouldPreserveNullTacacsCommands(ctx context.Context, prior types.Object, desired types.Object, diags *diag.Diagnostics) bool {
	if prior.IsNull() || prior.IsUnknown() || desired.IsNull() || desired.IsUnknown() {
		return false
	}

	var priorModel tacacsServiceParamModel
	var desiredModel tacacsServiceParamModel
	diags.Append(prior.As(ctx, &priorModel, basetypes.ObjectAsOptions{})...)
	diags.Append(desired.As(ctx, &desiredModel, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return false
	}

	if priorModel.TacacsCommandConfig.IsNull() || priorModel.TacacsCommandConfig.IsUnknown() || desiredModel.TacacsCommandConfig.IsNull() || desiredModel.TacacsCommandConfig.IsUnknown() {
		return false
	}

	var priorCfg tacacsCommandConfigModel
	var desiredCfg tacacsCommandConfigModel
	diags.Append(priorModel.TacacsCommandConfig.As(ctx, &priorCfg, basetypes.ObjectAsOptions{})...)
	diags.Append(desiredModel.TacacsCommandConfig.As(ctx, &desiredCfg, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return false
	}

	// Preserve only for stable null->null behavior. If prior had commands and desired removes
	// them, do not preserve; we must surface that drift/failure.
	return priorCfg.Commands.IsNull() && desiredCfg.Commands.IsNull()
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

func (m tacacsServiceParamModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"privilege_level":            types.Int64Type,
		"services":                   types.ListType{ElemType: types.StringType},
		"authorize_attribute_status": types.StringType,
		"tacacs_command_config":      types.ObjectType{AttrTypes: tacacsCommandConfigModel{}.attrTypes()},
	}
}

func (m tacacsCommandConfigModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"service_type":          types.StringType,
		"permit_unmatched_cmds": types.BoolType,
		"commands":              types.ListType{ElemType: types.ObjectType{AttrTypes: tacacsCommandModel{}.attrTypes()}},
	}
}

func (m tacacsCommandModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"command":               types.StringType,
		"permit_unmatched_args": types.BoolType,
		"command_args":          types.ListType{ElemType: types.ObjectType{AttrTypes: tacacsCommandArgsModel{}.attrTypes()}},
	}
}

func (m tacacsCommandArgsModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"argument":      types.StringType,
		"permit_action": types.BoolType,
	}
}

func expandTacacsServiceParams(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *client.TacacsServiceParam {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var model tacacsServiceParamModel
	diags.Append(obj.As(ctx, &model, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	apiParam := &client.TacacsServiceParam{}
	if !model.PrivilegeLevel.IsNull() {
		level := int(model.PrivilegeLevel.ValueInt64())
		apiParam.PrivilegeLevel = &level
	}
	if !model.Services.IsNull() {
		var services []string
		diags.Append(model.Services.ElementsAs(ctx, &services, false)...)
		apiParam.Services = services
	}
	if !model.AuthorizeAttributeStatus.IsNull() {
		apiParam.AuthorizeAttributeStatus = model.AuthorizeAttributeStatus.ValueString()
	}
	if !model.TacacsCommandConfig.IsNull() && !model.TacacsCommandConfig.IsUnknown() {
		apiParam.TacacsCommandConfig = expandTacacsCommandConfig(ctx, model.TacacsCommandConfig, diags)
	}
	return apiParam
}

func expandTacacsCommandConfig(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *client.TacacsCommandConfig {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var model tacacsCommandConfigModel
	diags.Append(obj.As(ctx, &model, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	apiConfig := &client.TacacsCommandConfig{}
	if !model.ServiceType.IsNull() {
		apiConfig.ServiceType = model.ServiceType.ValueString()
	}
	if !model.PermitUnmatchedCmds.IsNull() {
		val := model.PermitUnmatchedCmds.ValueBool()
		apiConfig.PermitUnmatchedCmds = &val
	}
	if !model.Commands.IsNull() {
		var tfCommands []tacacsCommandModel
		diags.Append(model.Commands.ElementsAs(ctx, &tfCommands, false)...)
		var apiCommands []*client.TacacsCommand
		for _, tfCmd := range tfCommands {
			apiCmd := &client.TacacsCommand{}
			if !tfCmd.Command.IsNull() {
				apiCmd.Command = tfCmd.Command.ValueString()
			}
			if !tfCmd.PermitUnmatchedArgs.IsNull() {
				val := tfCmd.PermitUnmatchedArgs.ValueBool()
				apiCmd.PermitUnmatchedArgs = &val
			}
			if !tfCmd.CommandArgs.IsNull() {
				var tfArgs []tacacsCommandArgsModel
				diags.Append(tfCmd.CommandArgs.ElementsAs(ctx, &tfArgs, false)...)
				var apiArgs []*client.TacacsCommandArgs
				for _, tfArg := range tfArgs {
					apiArg := &client.TacacsCommandArgs{}
					if !tfArg.Argument.IsNull() {
						apiArg.Argument = tfArg.Argument.ValueString()
					}
					if !tfArg.PermitAction.IsNull() {
						val := tfArg.PermitAction.ValueBool()
						apiArg.PermitAction = &val
					}
					apiArgs = append(apiArgs, apiArg)
				}
				apiCmd.CommandArgs = apiArgs
			}
			apiCommands = append(apiCommands, apiCmd)
		}
		apiConfig.Commands = apiCommands
	}
	return apiConfig
}

func flattenTacacsServiceParams(ctx context.Context, apiParam *client.TacacsServiceParam) (types.Object, diag.Diagnostics) {
	if apiParam == nil {
		return types.ObjectNull(tacacsServiceParamModel{}.attrTypes()), nil
	}
	var diags diag.Diagnostics

	model := tacacsServiceParamModel{
		PrivilegeLevel:           types.Int64Null(),
		Services:                 types.ListNull(types.StringType),
		AuthorizeAttributeStatus: types.StringNull(),
		TacacsCommandConfig:      types.ObjectNull(tacacsCommandConfigModel{}.attrTypes()),
	}

	if apiParam.PrivilegeLevel != nil {
		model.PrivilegeLevel = types.Int64Value(int64(*apiParam.PrivilegeLevel))
	}
	if len(apiParam.Services) > 0 {
		servicesList, d := types.ListValueFrom(ctx, types.StringType, apiParam.Services)
		diags.Append(d...)
		model.Services = servicesList
	}
	if apiParam.AuthorizeAttributeStatus != "" {
		model.AuthorizeAttributeStatus = types.StringValue(apiParam.AuthorizeAttributeStatus)
	}
	if apiParam.TacacsCommandConfig != nil {
		configObj, d := flattenTacacsCommandConfig(ctx, apiParam.TacacsCommandConfig)
		diags.Append(d...)
		model.TacacsCommandConfig = configObj
	}

	return types.ObjectValueFrom(ctx, tacacsServiceParamModel{}.attrTypes(), model)
}

func flattenTacacsCommandConfig(ctx context.Context, apiConfig *client.TacacsCommandConfig) (types.Object, diag.Diagnostics) {
	if apiConfig == nil {
		return types.ObjectNull(tacacsCommandConfigModel{}.attrTypes()), nil
	}
	var diags diag.Diagnostics

	model := tacacsCommandConfigModel{
		ServiceType:         types.StringNull(),
		PermitUnmatchedCmds: types.BoolNull(),
		Commands:            types.ListNull(types.ObjectType{AttrTypes: tacacsCommandModel{}.attrTypes()}),
	}

	if apiConfig.ServiceType != "" {
		model.ServiceType = types.StringValue(apiConfig.ServiceType)
	}
	if apiConfig.PermitUnmatchedCmds != nil {
		model.PermitUnmatchedCmds = types.BoolValue(*apiConfig.PermitUnmatchedCmds)
	}
	if len(apiConfig.Commands) > 0 {
		var tfCommands []tacacsCommandModel
		for _, apiCmd := range apiConfig.Commands {
			tfCmd := tacacsCommandModel{
				Command:             types.StringNull(),
				PermitUnmatchedArgs: types.BoolNull(),
				CommandArgs:         types.ListNull(types.ObjectType{AttrTypes: tacacsCommandArgsModel{}.attrTypes()}),
			}
			if apiCmd.Command != "" {
				tfCmd.Command = types.StringValue(apiCmd.Command)
			}
			if apiCmd.PermitUnmatchedArgs != nil {
				tfCmd.PermitUnmatchedArgs = types.BoolValue(*apiCmd.PermitUnmatchedArgs)
			}
			if len(apiCmd.CommandArgs) > 0 {
				var tfArgs []tacacsCommandArgsModel
				for _, apiArg := range apiCmd.CommandArgs {
					tfArg := tacacsCommandArgsModel{
						Argument:     types.StringNull(),
						PermitAction: types.BoolNull(),
					}
					if apiArg.Argument != "" {
						tfArg.Argument = types.StringValue(apiArg.Argument)
					}
					if apiArg.PermitAction != nil {
						tfArg.PermitAction = types.BoolValue(*apiArg.PermitAction)
					}
					tfArgs = append(tfArgs, tfArg)
				}
				argsList, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: tacacsCommandArgsModel{}.attrTypes()}, tfArgs)
				diags.Append(d...)
				tfCmd.CommandArgs = argsList
			}
			tfCommands = append(tfCommands, tfCmd)
		}
		cmdList, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: tacacsCommandModel{}.attrTypes()}, tfCommands)
		diags.Append(d...)
		model.Commands = cmdList
	}

	return types.ObjectValueFrom(ctx, tacacsCommandConfigModel{}.attrTypes(), model)
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

// preserveNullTacacsCommands re-applies the user's original null intent onto the
// API-flattened result so that omitted (null) ``commands`` or
// ``tacacs_command_config`` blocks do not cause spurious plan differences.
//
// After flattenTacacsServiceParams returns the API-read value we need to patch
// any field that the user deliberately left as null: the API may echo back an
// empty list or a partially-populated object, which Terraform would otherwise
// treat as a diff against the user's null.
func preserveNullTacacsCommands(ctx context.Context, desired types.Object, result *types.Object, diags *diag.Diagnostics) {
	if desired.IsNull() || desired.IsUnknown() {
		return
	}
	if result == nil || result.IsNull() || result.IsUnknown() {
		return
	}

	// ── decode desired model ──────────────────────────────────────────────────
	var desiredModel tacacsServiceParamModel
	diags.Append(desired.As(ctx, &desiredModel, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return
	}

	// If the user omitted tacacs_command_config entirely, preserve null.
	if desiredModel.TacacsCommandConfig.IsNull() {
		var resultModel tacacsServiceParamModel
		diags.Append(result.As(ctx, &resultModel, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return
		}
		resultModel.TacacsCommandConfig = types.ObjectNull(tacacsCommandConfigModel{}.attrTypes())
		newResult, d := types.ObjectValueFrom(ctx, tacacsServiceParamModel{}.attrTypes(), resultModel)
		diags.Append(d...)
		*result = newResult
		return
	}

	// ── decode desired command-config ─────────────────────────────────────────
	var desiredConfig tacacsCommandConfigModel
	diags.Append(desiredModel.TacacsCommandConfig.As(ctx, &desiredConfig, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return
	}

	// If the user omitted commands entirely (null), preserve null in the result.
	// Also treat empty lists as a desire to clear commands.
	if desiredConfig.Commands.IsNull() || len(desiredConfig.Commands.Elements()) == 0 {
		var resultModel tacacsServiceParamModel
		diags.Append(result.As(ctx, &resultModel, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return
		}
		if resultModel.TacacsCommandConfig.IsNull() || resultModel.TacacsCommandConfig.IsUnknown() {
			return
		}
		var resultConfig tacacsCommandConfigModel
		diags.Append(resultModel.TacacsCommandConfig.As(ctx, &resultConfig, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return
		}
		resultConfig.Commands = types.ListNull(types.ObjectType{AttrTypes: tacacsCommandModel{}.attrTypes()})
		newConfig, d := types.ObjectValueFrom(ctx, tacacsCommandConfigModel{}.attrTypes(), resultConfig)
		diags.Append(d...)
		resultModel.TacacsCommandConfig = newConfig
		newResult, d := types.ObjectValueFrom(ctx, tacacsServiceParamModel{}.attrTypes(), resultModel)
		diags.Append(d...)
		*result = newResult
	}
}
