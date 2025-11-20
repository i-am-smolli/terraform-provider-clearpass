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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	stringdefault "github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
)

var _ resource.Resource = &serviceResource{}

type serviceResource struct {
	client client.ClientInterface
}

type serviceModel struct {
	ID                types.Int64  `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Type              types.String `tfsdk:"type"`
	Template          types.String `tfsdk:"template"`
	Description       types.String `tfsdk:"description"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	AuthMethods       types.List   `tfsdk:"auth_methods"` // List of strings
	AuthSources       types.List   `tfsdk:"auth_sources"` // List of strings
	RoleMappingPolicy types.String `tfsdk:"role_mapping_policy"`
	EnfPolicy         types.String `tfsdk:"enforcement_policy"` // Renamed for clarity in HCL
	StripUsername     types.Bool   `tfsdk:"strip_username"`
	MatchType   	  types.String `tfsdk:"match_type"`   // MATCHES_ALL / MATCHES_ANY
	ServiceRule 	  types.List   `tfsdk:"service_rule"` // List of serviceRuleModel
}

type serviceRuleModel struct {
	Type     types.String `tfsdk:"type"`
	Name     types.String `tfsdk:"name"`
	Operator types.String `tfsdk:"operator"`
	Value    types.String `tfsdk:"value"`
}

func NewServiceResource() resource.Resource {
	return &serviceResource{}
}

func (r *serviceResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service"
}

func (r *serviceResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a ClearPass Service.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description:   "Numeric ID of the service.",
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Description: "Name of the Service.",
				Required:    true,
			},
			"template": schema.StringAttribute{
				Description: "Service Template (e.g. '802.1X Wireless').",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Description:   "Service Type (e.g. 'RADIUS', 'TACACS').",
				Optional:      false,
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"description": schema.StringAttribute{
				Description:   "Description of the Service.",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"enabled": schema.BoolAttribute{
				Description:   "Is Service enabled? Defaults to false.",
				Optional:      true,
				Computed:      true,
				Default:       booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"match_type": schema.StringAttribute{
							Description: "Rules match type ('MATCHES_ALL' or 'MATCHES_ANY'). Defaults to 'MATCHES_ALL'.",
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString("MATCHES_ALL"),
			},
			"service_rule": schema.ListNestedAttribute{
				Description: "List of matching rules for this service.",
				Optional:    true, // Optional, because some Services are "Catch All"
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							Description: "Type of the rule (e.g., 'Radius:IETF').",
							Required:    true,
						},
						"name": schema.StringAttribute{
							Description: "Name of the rule attribute (e.g., 'NAS-Port-Type').",
							Required:    true,
						},
						"operator": schema.StringAttribute{
							Description: "Operator (e.g., 'EQUALS', 'NOT_EQUALS').",
							Required:    true,
						},
						"value": schema.StringAttribute{
							Description: "Value to match.",
							Required:    true,
						},
					},
				},
			},
			"strip_username": schema.BoolAttribute{
				Description:   "Strip Username",
				Optional:      true,
				Computed:      true,
				Default:       booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"auth_methods": schema.ListAttribute{
				Description: "List of Authentication Methods.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"auth_sources": schema.ListAttribute{
				Description: "List of Authentication Sources.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"role_mapping_policy": schema.StringAttribute{
				Description: "Name of the Role Mapping Policy.",
				Optional:    true,
			},
			"enforcement_policy": schema.StringAttribute{ // Maps to 'enf_policy' in API
				Description: "Name of the Enforcement Policy.",
				Required:    true, // Most services need an enforcement policy
			},
		},
	}
}

func (r *serviceResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *serviceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serviceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert TF lists to Go slices
	var authMethods, authSources []string
	resp.Diagnostics.Append(plan.AuthMethods.ElementsAs(ctx, &authMethods, false)...) // Convert Terraform list to Go slice
	resp.Diagnostics.Append(plan.AuthSources.ElementsAs(ctx, &authSources, false)...) // Convert Terraform list to Go slice

	enabled := plan.Enabled.ValueBool()
	strip := plan.StripUsername.ValueBool()

	apiPayload := &client.ServiceCreate{
		Name:              plan.Name.ValueString(),
		Template:          plan.Template.ValueString(),
		Type:              plan.Type.ValueString(),
		Description:       plan.Description.ValueString(),
		Enabled:           &enabled,
		StripUsername:     &strip,
		AuthMethods:       authMethods,
		AuthSources:       authSources,
		EnfPolicy:         plan.EnfPolicy.ValueString(),
		RoleMappingPolicy: plan.RoleMappingPolicy.ValueString(),
		RulesMatchType:    plan.MatchType.ValueString(),
		RulesConditions:   expandServiceRules(ctx, plan.ServiceRule, &resp.Diagnostics),
	}

	created, err := r.client.CreateService(ctx, apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
		return
	}

	// Map back
	plan.ID = types.Int64Value(int64(created.ID))
	plan.Name = types.StringValue(created.Name)
	plan.Template = types.StringValue(created.Template)
	plan.Enabled = types.BoolValue(created.Enabled)
	plan.StripUsername = types.BoolValue(created.StripUsername)
	plan.EnfPolicy = types.StringValue(created.EnfPolicy)
	

	// Fix for optional fields: If API returns "", store null
	if created.RoleMappingPolicy == "" {
		plan.RoleMappingPolicy = types.StringNull()
	} else {
		plan.RoleMappingPolicy = types.StringValue(created.RoleMappingPolicy)
	}

	if created.Description == "" {
		plan.Description = types.StringNull()
	} else {
		plan.Description = types.StringValue(created.Description)
	}

	if created.Type == "" {
		plan.Type = types.StringNull()
	} else {
		plan.Type = types.StringValue(created.Type)
	}

	plan.AuthMethods, _ = types.ListValueFrom(ctx, types.StringType, created.AuthMethods)
	plan.AuthSources, _ = types.ListValueFrom(ctx, types.StringType, created.AuthSources)

	plan.MatchType = types.StringValue(created.RulesMatchType)
	var diags diag.Diagnostics
    plan.ServiceRule, diags = flattenServiceRules(ctx, created.RulesConditions)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...) // Set the state
}

func (r *serviceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serviceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	service, err := r.client.GetService(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
		return
	}
	if service == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.Name = types.StringValue(service.Name)
	state.Template = types.StringValue(service.Template)
	state.Enabled = types.BoolValue(service.Enabled)
	state.StripUsername = types.BoolValue(service.StripUsername)
	state.EnfPolicy = types.StringValue(service.EnfPolicy)

	if service.RoleMappingPolicy == "" {
		state.RoleMappingPolicy = types.StringNull()
	} else {
		state.RoleMappingPolicy = types.StringValue(service.RoleMappingPolicy)
	}

	if service.Description == "" {
		state.Description = types.StringNull()
	} else {
		state.Description = types.StringValue(service.Description)
	}

	if service.Type == "" {
		state.Type = types.StringNull()
	} else {
		state.Type = types.StringValue(service.Type)
	}

	state.AuthMethods, _ = types.ListValueFrom(ctx, types.StringType, service.AuthMethods)
	state.AuthSources, _ = types.ListValueFrom(ctx, types.StringType, service.AuthSources)

	state.MatchType = types.StringValue(service.RulesMatchType)
	var diags diag.Diagnostics
    state.ServiceRule, diags = flattenServiceRules(ctx, service.RulesConditions)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *serviceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan serviceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPayload := &client.ServiceUpdate{}

	if !plan.Name.IsUnknown() {
		apiPayload.Name = plan.Name.ValueString()
	}
	if !plan.Description.IsUnknown() {
		apiPayload.Description = plan.Description.ValueString()
	}
	if !plan.Template.IsUnknown() {
		apiPayload.Template = plan.Template.ValueString()
	}

	if !plan.Enabled.IsUnknown() {
		val := plan.Enabled.ValueBool()
		apiPayload.Enabled = &val
	}
	if !plan.StripUsername.IsUnknown() {
		val := plan.StripUsername.ValueBool()
		apiPayload.StripUsername = &val
	}

	if !plan.EnfPolicy.IsUnknown() {
		apiPayload.EnfPolicy = plan.EnfPolicy.ValueString()
	}
	if !plan.RoleMappingPolicy.IsUnknown() {
		apiPayload.RoleMappingPolicy = plan.RoleMappingPolicy.ValueString()
	}

	if !plan.AuthMethods.IsUnknown() {
		var am []string
		plan.AuthMethods.ElementsAs(ctx, &am, false)
		apiPayload.AuthMethods = am
	}
	if !plan.AuthSources.IsUnknown() {
		var as []string
		plan.AuthSources.ElementsAs(ctx, &as, false)
		apiPayload.AuthSources = as
	}
	if !plan.MatchType.IsUnknown() {
        apiPayload.RulesMatchType = plan.MatchType.ValueString()
    }
	apiPayload.RulesConditions = expandServiceRules(ctx, plan.ServiceRule, &resp.Diagnostics)

	updated, err := r.client.UpdateService(ctx, int(plan.ID.ValueInt64()), apiPayload)
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
		return
	}

	// Update state
	plan.Name = types.StringValue(updated.Name)
	plan.Enabled = types.BoolValue(updated.Enabled)
	plan.StripUsername = types.BoolValue(updated.StripUsername)
	plan.EnfPolicy = types.StringValue(updated.EnfPolicy)

	if updated.RoleMappingPolicy == "" {
		plan.RoleMappingPolicy = types.StringNull()
	} else {
		plan.RoleMappingPolicy = types.StringValue(updated.RoleMappingPolicy)
	}

	if updated.Description == "" {
		plan.Description = types.StringNull()
	} else {
		plan.Description = types.StringValue(updated.Description)
	}

	// Type usually does not change on update, but just to be sure:
	if updated.Type == "" {
		// Here we use PlanValue, because Type is computed in the schema and we might not have it in the update response
		// Better: just ignore in update, or:
		plan.Type = types.StringValue(updated.Type)
	}
	plan.MatchType = types.StringValue(updated.RulesMatchType)
	var diags diag.Diagnostics
    plan.ServiceRule, diags = flattenServiceRules(ctx, updated.RulesConditions)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serviceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.DeleteService(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
	}
}

func (r *serviceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	numericID, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Import ID", fmt.Sprintf("Expected numeric ID, got %q", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), numericID)...)
}

func expandServiceRules(ctx context.Context, list types.List, diags *diag.Diagnostics) []*client.ServiceRule {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var tfRules []serviceRuleModel
	diags.Append(list.ElementsAs(ctx, &tfRules, false)...)
	if diags.HasError() {
		return nil
	}

	var apiRules []*client.ServiceRule
	for _, item := range tfRules {
		apiRules = append(apiRules, &client.ServiceRule{
			Type:     item.Type.ValueString(),
			Name:     item.Name.ValueString(),
			Operator: item.Operator.ValueString(),
			Value:    item.Value.ValueString(),
		})
	}
	return apiRules
}

func flattenServiceRules(ctx context.Context, apiRules []*client.ServiceRule) (types.List, diag.Diagnostics) {
	if len(apiRules) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: serviceRuleModel{}.attrTypes()}), nil
	}
	var tfRules []serviceRuleModel
	for _, item := range apiRules {
		tfRules = append(tfRules, serviceRuleModel{
			Type:     types.StringValue(item.Type),
			Name:     types.StringValue(item.Name),
			Operator: types.StringValue(item.Operator),
			Value:    types.StringValue(item.Value),
		})
	}
	return types.ListValueFrom(ctx, types.ObjectType{AttrTypes: serviceRuleModel{}.attrTypes()}, tfRules)
}

func (m serviceRuleModel) attrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type":     types.StringType,
		"name":     types.StringType,
		"operator": types.StringType,
		"value":    types.StringType,
	}
}