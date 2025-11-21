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
	stringdefault "github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &serviceResource{}

type serviceResource struct {
	client client.ClientInterface
}

type serviceModel struct {
	ID                             types.Int64  `tfsdk:"id"`
	Name                           types.String `tfsdk:"name"`
	Type                           types.String `tfsdk:"type"`
	Template                       types.String `tfsdk:"template"`
	Description                    types.String `tfsdk:"description"`
	Enabled                        types.Bool   `tfsdk:"enabled"`
	AuthMethods                    types.List   `tfsdk:"auth_methods"` // List of strings
	AuthSources                    types.List   `tfsdk:"auth_sources"` // List of strings
	RoleMappingPolicy              types.String `tfsdk:"role_mapping_policy"`
	EnfPolicy                      types.String `tfsdk:"enforcement_policy"` // Renamed for clarity in HCL
	StripUsername                  types.Bool   `tfsdk:"strip_username"`
	MatchType                      types.String `tfsdk:"match_type"`   // MATCHES_ALL / MATCHES_ANY
	ServiceRule                    types.List   `tfsdk:"service_rule"` // List of serviceRuleModel
	DefaultPostureToken            types.String `tfsdk:"default_posture_token"`
	PosturePolicies                types.List   `tfsdk:"posture_policies"` // List of strings
	MonitorMode                    types.Bool   `tfsdk:"monitor_mode"`
	StripUsernameCSV               types.String `tfsdk:"strip_username_csv"`
	ServiceCertCN                  types.String `tfsdk:"service_cert_cn"`
	UseCachedPolicyResults         types.Bool   `tfsdk:"use_cached_policy_results"`
	AuthzSources                   types.List   `tfsdk:"authz_sources"` // List of strings
	PostureEnabled                 types.Bool   `tfsdk:"posture_enabled"`
	RemediateEndHosts              types.Bool   `tfsdk:"remediate_end_hosts"`
	RemediationURL                 types.String `tfsdk:"remediation_url"`
	AuditEnabled                   types.Bool   `tfsdk:"audit_enabled"`
	AuditServer                    types.String `tfsdk:"audit_server"`
	AuditTriggerCondition          types.String `tfsdk:"audit_trigger_condition"`
	AuditMacAuthClientType         types.String `tfsdk:"audit_mac_auth_client_type"`
	ActionAfterAudit               types.String `tfsdk:"action_after_audit"`
	AuditCoaAction                 types.String `tfsdk:"audit_coa_action"` // Mapped to audit_coa_acton
	ProfilerEnabled                types.Bool   `tfsdk:"profiler_enabled"`
	ProfilerEndpointClassification types.List   `tfsdk:"profiler_endpoint_classification"` // List of strings
	ProfilerCoaAction              types.String `tfsdk:"profiler_coa_action"`
	AcctProxyEnabled               types.Bool   `tfsdk:"acct_proxy_enabled"`
	AcctProxyTargets               types.List   `tfsdk:"acct_proxy_targets"` // List of strings
	RadiusProxyScheme              types.String `tfsdk:"radius_proxy_scheme"`
	RadiusProxyTargets             types.List   `tfsdk:"radius_proxy_targets"` // List of strings
	RadiusProxyEnableForAcct       types.Bool   `tfsdk:"radius_proxy_enable_for_acct"`
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
			"default_posture_token": schema.StringAttribute{
				Description: "Default Posture Token.",
				Optional:    true,
			},
			"posture_policies": schema.ListAttribute{
				Description: "List of Posture Policies.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"monitor_mode": schema.BoolAttribute{
				Description: "Enable to monitor network access without enforcement.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"strip_username_csv": schema.StringAttribute{
				Description: "Strip Username Rule (comma-separated).",
				Optional:    true,
			},
			"service_cert_cn": schema.StringAttribute{
				Description: "Subject DN of Service Certificate.",
				Optional:    true,
			},
			"use_cached_policy_results": schema.BoolAttribute{
				Description: "Enable to use cached Roles and Posture attributes from previous sessions.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"authz_sources": schema.ListAttribute{
				Description: "List of Additional authorization sources.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"posture_enabled": schema.BoolAttribute{
				Description: "Enable Posture Compliance.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"remediate_end_hosts": schema.BoolAttribute{
				Description: "Enable auto-remediation of non-compliant end-hosts.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"remediation_url": schema.StringAttribute{
				Description: "Remediation URL.",
				Optional:    true,
			},
			"audit_enabled": schema.BoolAttribute{
				Description: "Enable Audit End-hosts.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"audit_server": schema.StringAttribute{
				Description: "Audit Server Name.",
				Optional:    true,
			},
			"audit_trigger_condition": schema.StringAttribute{
				Description: "Audit Trigger Conditions (ALWAYS, NO_POSTURE, MAC_AUTH).",
				Optional:    true,
			},
			"audit_mac_auth_client_type": schema.StringAttribute{
				Description: "Client Type For MAC authentication request Audit Trigger Condition (KNOWN, UNKNOWN, BOTH).",
				Optional:    true,
			},
			"action_after_audit": schema.StringAttribute{
				Description: "Action after audit (NONE, SNMP, RADIUS).",
				Optional:    true,
			},
			"audit_coa_action": schema.StringAttribute{
				Description: "RADIUS CoA Action to be triggered after audit.",
				Optional:    true,
			},
			"profiler_enabled": schema.BoolAttribute{
				Description: "Enable Profile Endpoints.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"profiler_endpoint_classification": schema.ListAttribute{
				Description: "List of Endpoint classification(s) after which an action must be triggered.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"profiler_coa_action": schema.StringAttribute{
				Description: "RADIUS CoA Action to be triggered by Profiler.",
				Optional:    true,
			},
			"acct_proxy_enabled": schema.BoolAttribute{
				Description: "Enable Accounting Proxy Targets.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"acct_proxy_targets": schema.ListAttribute{
				Description: "List Accounting Proxy Target names.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"radius_proxy_scheme": schema.StringAttribute{
				Description: "Proxying Scheme for RADIUS Proxy Service Type (Load Balance, Failover).",
				Optional:    true,
			},
			"radius_proxy_targets": schema.ListAttribute{
				Description: "List of Proxy Targets for RADIUS Proxy Service Type.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"radius_proxy_enable_for_acct": schema.BoolAttribute{
				Description: "Enable proxy for accounting requests (Applicable only for RADIUS Proxy Service Type).",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
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
	var authMethods, authSources, posturePolicies, authzSources, profilerEndpointClassification, acctProxyTargets, radiusProxyTargets []string
	resp.Diagnostics.Append(plan.AuthMethods.ElementsAs(ctx, &authMethods, false)...) // Convert Terraform list to Go slice
	resp.Diagnostics.Append(plan.AuthSources.ElementsAs(ctx, &authSources, false)...) // Convert Terraform list to Go slice
	resp.Diagnostics.Append(plan.PosturePolicies.ElementsAs(ctx, &posturePolicies, false)...)
	resp.Diagnostics.Append(plan.AuthzSources.ElementsAs(ctx, &authzSources, false)...)
	resp.Diagnostics.Append(plan.ProfilerEndpointClassification.ElementsAs(ctx, &profilerEndpointClassification, false)...)
	resp.Diagnostics.Append(plan.AcctProxyTargets.ElementsAs(ctx, &acctProxyTargets, false)...)
	resp.Diagnostics.Append(plan.RadiusProxyTargets.ElementsAs(ctx, &radiusProxyTargets, false)...)

	enabled := plan.Enabled.ValueBool()
	strip := plan.StripUsername.ValueBool()
	monitorMode := plan.MonitorMode.ValueBool()
	useCached := plan.UseCachedPolicyResults.ValueBool()
	postureEnabled := plan.PostureEnabled.ValueBool()
	remediate := plan.RemediateEndHosts.ValueBool()
	auditEnabled := plan.AuditEnabled.ValueBool()
	profilerEnabled := plan.ProfilerEnabled.ValueBool()
	acctProxyEnabled := plan.AcctProxyEnabled.ValueBool()
	radiusProxyAcct := plan.RadiusProxyEnableForAcct.ValueBool()

	apiPayload := &client.ServiceCreate{
		Name:                           plan.Name.ValueString(),
		Template:                       plan.Template.ValueString(),
		Type:                           plan.Type.ValueString(),
		Description:                    plan.Description.ValueString(),
		Enabled:                        &enabled,
		StripUsername:                  &strip,
		AuthMethods:                    authMethods,
		AuthSources:                    authSources,
		EnfPolicy:                      plan.EnfPolicy.ValueString(),
		RoleMappingPolicy:              plan.RoleMappingPolicy.ValueString(),
		RulesMatchType:                 plan.MatchType.ValueString(),
		RulesConditions:                expandServiceRules(ctx, plan.ServiceRule, &resp.Diagnostics),
		DefaultPostureToken:            plan.DefaultPostureToken.ValueString(),
		PosturePolicies:                posturePolicies,
		MonitorMode:                    &monitorMode,
		StripUsernameCSV:               plan.StripUsernameCSV.ValueString(),
		ServiceCertCN:                  plan.ServiceCertCN.ValueString(),
		UseCachedPolicyResults:         &useCached,
		AuthzSources:                   authzSources,
		PostureEnabled:                 &postureEnabled,
		RemediateEndHosts:              &remediate,
		RemediationURL:                 plan.RemediationURL.ValueString(),
		AuditEnabled:                   &auditEnabled,
		AuditServer:                    plan.AuditServer.ValueString(),
		AuditTriggerCondition:          plan.AuditTriggerCondition.ValueString(),
		AuditMacAuthClientType:         plan.AuditMacAuthClientType.ValueString(),
		ActionAfterAudit:               plan.ActionAfterAudit.ValueString(),
		AuditCoaAction:                 plan.AuditCoaAction.ValueString(),
		ProfilerEnabled:                &profilerEnabled,
		ProfilerEndpointClassification: profilerEndpointClassification,
		ProfilerCoaAction:              plan.ProfilerCoaAction.ValueString(),
		AcctProxyEnabled:               &acctProxyEnabled,
		AcctProxyTargets:               acctProxyTargets,
		RadiusProxyScheme:              plan.RadiusProxyScheme.ValueString(),
		RadiusProxyTargets:             radiusProxyTargets,
		RadiusProxyEnableForAcct:       &radiusProxyAcct,
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
	plan.PosturePolicies, _ = types.ListValueFrom(ctx, types.StringType, created.PosturePolicies)
	plan.AuthzSources, _ = types.ListValueFrom(ctx, types.StringType, created.AuthzSources)
	plan.ProfilerEndpointClassification, _ = types.ListValueFrom(ctx, types.StringType, created.ProfilerEndpointClassification)
	plan.AcctProxyTargets, _ = types.ListValueFrom(ctx, types.StringType, created.AcctProxyTargets)
	plan.RadiusProxyTargets, _ = types.ListValueFrom(ctx, types.StringType, created.RadiusProxyTargets)

	if created.DefaultPostureToken == "" {
		plan.DefaultPostureToken = types.StringNull()
	} else {
		plan.DefaultPostureToken = types.StringValue(created.DefaultPostureToken)
	}

	plan.MonitorMode = types.BoolValue(created.MonitorMode)
	if created.StripUsernameCSV == "" {
		plan.StripUsernameCSV = types.StringNull()
	} else {
		plan.StripUsernameCSV = types.StringValue(created.StripUsernameCSV)
	}
	if created.ServiceCertCN == "" {
		plan.ServiceCertCN = types.StringNull()
	} else {
		plan.ServiceCertCN = types.StringValue(created.ServiceCertCN)
	}
	plan.UseCachedPolicyResults = types.BoolValue(created.UseCachedPolicyResults)
	plan.PostureEnabled = types.BoolValue(created.PostureEnabled)
	plan.RemediateEndHosts = types.BoolValue(created.RemediateEndHosts)
	if created.RemediationURL == "" {
		plan.RemediationURL = types.StringNull()
	} else {
		plan.RemediationURL = types.StringValue(created.RemediationURL)
	}
	plan.AuditEnabled = types.BoolValue(created.AuditEnabled)
	if created.AuditServer == "" {
		plan.AuditServer = types.StringNull()
	} else {
		plan.AuditServer = types.StringValue(created.AuditServer)
	}
	if created.AuditTriggerCondition == "" {
		plan.AuditTriggerCondition = types.StringNull()
	} else {
		plan.AuditTriggerCondition = types.StringValue(created.AuditTriggerCondition)
	}
	if created.AuditMacAuthClientType == "" {
		plan.AuditMacAuthClientType = types.StringNull()
	} else {
		plan.AuditMacAuthClientType = types.StringValue(created.AuditMacAuthClientType)
	}
	if created.ActionAfterAudit == "" {
		plan.ActionAfterAudit = types.StringNull()
	} else {
		plan.ActionAfterAudit = types.StringValue(created.ActionAfterAudit)
	}
	if created.AuditCoaAction == "" {
		plan.AuditCoaAction = types.StringNull()
	} else {
		plan.AuditCoaAction = types.StringValue(created.AuditCoaAction)
	}
	plan.ProfilerEnabled = types.BoolValue(created.ProfilerEnabled)
	if created.ProfilerCoaAction == "" {
		plan.ProfilerCoaAction = types.StringNull()
	} else {
		plan.ProfilerCoaAction = types.StringValue(created.ProfilerCoaAction)
	}
	plan.AcctProxyEnabled = types.BoolValue(created.AcctProxyEnabled)
	if created.RadiusProxyScheme == "" {
		plan.RadiusProxyScheme = types.StringNull()
	} else {
		plan.RadiusProxyScheme = types.StringValue(created.RadiusProxyScheme)
	}
	plan.RadiusProxyEnableForAcct = types.BoolValue(created.RadiusProxyEnableForAcct)

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
	state.PosturePolicies, _ = types.ListValueFrom(ctx, types.StringType, service.PosturePolicies)
	state.AuthzSources, _ = types.ListValueFrom(ctx, types.StringType, service.AuthzSources)
	state.ProfilerEndpointClassification, _ = types.ListValueFrom(ctx, types.StringType, service.ProfilerEndpointClassification)
	state.AcctProxyTargets, _ = types.ListValueFrom(ctx, types.StringType, service.AcctProxyTargets)
	state.RadiusProxyTargets, _ = types.ListValueFrom(ctx, types.StringType, service.RadiusProxyTargets)

	if service.DefaultPostureToken == "" {
		state.DefaultPostureToken = types.StringNull()
	} else {
		state.DefaultPostureToken = types.StringValue(service.DefaultPostureToken)
	}

	state.MonitorMode = types.BoolValue(service.MonitorMode)
	if service.StripUsernameCSV == "" {
		state.StripUsernameCSV = types.StringNull()
	} else {
		state.StripUsernameCSV = types.StringValue(service.StripUsernameCSV)
	}
	if service.ServiceCertCN == "" {
		state.ServiceCertCN = types.StringNull()
	} else {
		state.ServiceCertCN = types.StringValue(service.ServiceCertCN)
	}
	state.UseCachedPolicyResults = types.BoolValue(service.UseCachedPolicyResults)
	state.PostureEnabled = types.BoolValue(service.PostureEnabled)
	state.RemediateEndHosts = types.BoolValue(service.RemediateEndHosts)
	if service.RemediationURL == "" {
		state.RemediationURL = types.StringNull()
	} else {
		state.RemediationURL = types.StringValue(service.RemediationURL)
	}
	state.AuditEnabled = types.BoolValue(service.AuditEnabled)
	if service.AuditServer == "" {
		state.AuditServer = types.StringNull()
	} else {
		state.AuditServer = types.StringValue(service.AuditServer)
	}
	if service.AuditTriggerCondition == "" {
		state.AuditTriggerCondition = types.StringNull()
	} else {
		state.AuditTriggerCondition = types.StringValue(service.AuditTriggerCondition)
	}
	if service.AuditMacAuthClientType == "" {
		state.AuditMacAuthClientType = types.StringNull()
	} else {
		state.AuditMacAuthClientType = types.StringValue(service.AuditMacAuthClientType)
	}
	if service.ActionAfterAudit == "" {
		state.ActionAfterAudit = types.StringNull()
	} else {
		state.ActionAfterAudit = types.StringValue(service.ActionAfterAudit)
	}
	if service.AuditCoaAction == "" {
		state.AuditCoaAction = types.StringNull()
	} else {
		state.AuditCoaAction = types.StringValue(service.AuditCoaAction)
	}
	state.ProfilerEnabled = types.BoolValue(service.ProfilerEnabled)
	if service.ProfilerCoaAction == "" {
		state.ProfilerCoaAction = types.StringNull()
	} else {
		state.ProfilerCoaAction = types.StringValue(service.ProfilerCoaAction)
	}
	state.AcctProxyEnabled = types.BoolValue(service.AcctProxyEnabled)
	if service.RadiusProxyScheme == "" {
		state.RadiusProxyScheme = types.StringNull()
	} else {
		state.RadiusProxyScheme = types.StringValue(service.RadiusProxyScheme)
	}
	state.RadiusProxyEnableForAcct = types.BoolValue(service.RadiusProxyEnableForAcct)

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
	if !plan.AuthzSources.IsUnknown() {
		var azs []string
		plan.AuthzSources.ElementsAs(ctx, &azs, false)
		apiPayload.AuthzSources = azs
	}
	if !plan.ProfilerEndpointClassification.IsUnknown() {
		var pec []string
		plan.ProfilerEndpointClassification.ElementsAs(ctx, &pec, false)
		apiPayload.ProfilerEndpointClassification = pec
	}
	if !plan.AcctProxyTargets.IsUnknown() {
		var apt []string
		plan.AcctProxyTargets.ElementsAs(ctx, &apt, false)
		apiPayload.AcctProxyTargets = apt
	}
	if !plan.RadiusProxyTargets.IsUnknown() {
		var rpt []string
		plan.RadiusProxyTargets.ElementsAs(ctx, &rpt, false)
		apiPayload.RadiusProxyTargets = rpt
	}
	if !plan.DefaultPostureToken.IsUnknown() {
		apiPayload.DefaultPostureToken = plan.DefaultPostureToken.ValueString()
	}
	if !plan.PosturePolicies.IsUnknown() {
		var pp []string
		plan.PosturePolicies.ElementsAs(ctx, &pp, false)
		apiPayload.PosturePolicies = pp
	}
	if !plan.MonitorMode.IsUnknown() {
		val := plan.MonitorMode.ValueBool()
		apiPayload.MonitorMode = &val
	}
	if !plan.StripUsernameCSV.IsUnknown() {
		apiPayload.StripUsernameCSV = plan.StripUsernameCSV.ValueString()
	}
	if !plan.ServiceCertCN.IsUnknown() {
		apiPayload.ServiceCertCN = plan.ServiceCertCN.ValueString()
	}
	if !plan.UseCachedPolicyResults.IsUnknown() {
		val := plan.UseCachedPolicyResults.ValueBool()
		apiPayload.UseCachedPolicyResults = &val
	}
	if !plan.PostureEnabled.IsUnknown() {
		val := plan.PostureEnabled.ValueBool()
		apiPayload.PostureEnabled = &val
	}
	if !plan.RemediateEndHosts.IsUnknown() {
		val := plan.RemediateEndHosts.ValueBool()
		apiPayload.RemediateEndHosts = &val
	}
	if !plan.RemediationURL.IsUnknown() {
		apiPayload.RemediationURL = plan.RemediationURL.ValueString()
	}
	if !plan.AuditEnabled.IsUnknown() {
		val := plan.AuditEnabled.ValueBool()
		apiPayload.AuditEnabled = &val
	}
	if !plan.AuditServer.IsUnknown() {
		apiPayload.AuditServer = plan.AuditServer.ValueString()
	}
	if !plan.AuditTriggerCondition.IsUnknown() {
		apiPayload.AuditTriggerCondition = plan.AuditTriggerCondition.ValueString()
	}
	if !plan.AuditMacAuthClientType.IsUnknown() {
		apiPayload.AuditMacAuthClientType = plan.AuditMacAuthClientType.ValueString()
	}
	if !plan.ActionAfterAudit.IsUnknown() {
		apiPayload.ActionAfterAudit = plan.ActionAfterAudit.ValueString()
	}
	if !plan.AuditCoaAction.IsUnknown() {
		apiPayload.AuditCoaAction = plan.AuditCoaAction.ValueString()
	}
	if !plan.ProfilerEnabled.IsUnknown() {
		val := plan.ProfilerEnabled.ValueBool()
		apiPayload.ProfilerEnabled = &val
	}
	if !plan.ProfilerCoaAction.IsUnknown() {
		apiPayload.ProfilerCoaAction = plan.ProfilerCoaAction.ValueString()
	}
	if !plan.AcctProxyEnabled.IsUnknown() {
		val := plan.AcctProxyEnabled.ValueBool()
		apiPayload.AcctProxyEnabled = &val
	}
	if !plan.RadiusProxyScheme.IsUnknown() {
		apiPayload.RadiusProxyScheme = plan.RadiusProxyScheme.ValueString()
	}
	if !plan.RadiusProxyEnableForAcct.IsUnknown() {
		val := plan.RadiusProxyEnableForAcct.ValueBool()
		apiPayload.RadiusProxyEnableForAcct = &val
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

	plan.PosturePolicies, _ = types.ListValueFrom(ctx, types.StringType, updated.PosturePolicies)
	plan.AuthzSources, _ = types.ListValueFrom(ctx, types.StringType, updated.AuthzSources)
	plan.ProfilerEndpointClassification, _ = types.ListValueFrom(ctx, types.StringType, updated.ProfilerEndpointClassification)
	plan.AcctProxyTargets, _ = types.ListValueFrom(ctx, types.StringType, updated.AcctProxyTargets)
	plan.RadiusProxyTargets, _ = types.ListValueFrom(ctx, types.StringType, updated.RadiusProxyTargets)

	if updated.DefaultPostureToken == "" {
		plan.DefaultPostureToken = types.StringNull()
	} else {
		plan.DefaultPostureToken = types.StringValue(updated.DefaultPostureToken)
	}

	plan.MonitorMode = types.BoolValue(updated.MonitorMode)
	if updated.StripUsernameCSV == "" {
		plan.StripUsernameCSV = types.StringNull()
	} else {
		plan.StripUsernameCSV = types.StringValue(updated.StripUsernameCSV)
	}
	if updated.ServiceCertCN == "" {
		plan.ServiceCertCN = types.StringNull()
	} else {
		plan.ServiceCertCN = types.StringValue(updated.ServiceCertCN)
	}
	plan.UseCachedPolicyResults = types.BoolValue(updated.UseCachedPolicyResults)
	plan.PostureEnabled = types.BoolValue(updated.PostureEnabled)
	plan.RemediateEndHosts = types.BoolValue(updated.RemediateEndHosts)
	if updated.RemediationURL == "" {
		plan.RemediationURL = types.StringNull()
	} else {
		plan.RemediationURL = types.StringValue(updated.RemediationURL)
	}
	plan.AuditEnabled = types.BoolValue(updated.AuditEnabled)
	if updated.AuditServer == "" {
		plan.AuditServer = types.StringNull()
	} else {
		plan.AuditServer = types.StringValue(updated.AuditServer)
	}
	if updated.AuditTriggerCondition == "" {
		plan.AuditTriggerCondition = types.StringNull()
	} else {
		plan.AuditTriggerCondition = types.StringValue(updated.AuditTriggerCondition)
	}
	if updated.AuditMacAuthClientType == "" {
		plan.AuditMacAuthClientType = types.StringNull()
	} else {
		plan.AuditMacAuthClientType = types.StringValue(updated.AuditMacAuthClientType)
	}
	if updated.ActionAfterAudit == "" {
		plan.ActionAfterAudit = types.StringNull()
	} else {
		plan.ActionAfterAudit = types.StringValue(updated.ActionAfterAudit)
	}
	if updated.AuditCoaAction == "" {
		plan.AuditCoaAction = types.StringNull()
	} else {
		plan.AuditCoaAction = types.StringValue(updated.AuditCoaAction)
	}
	plan.ProfilerEnabled = types.BoolValue(updated.ProfilerEnabled)
	if updated.ProfilerCoaAction == "" {
		plan.ProfilerCoaAction = types.StringNull()
	} else {
		plan.ProfilerCoaAction = types.StringValue(updated.ProfilerCoaAction)
	}
	plan.AcctProxyEnabled = types.BoolValue(updated.AcctProxyEnabled)
	if updated.RadiusProxyScheme == "" {
		plan.RadiusProxyScheme = types.StringNull()
	} else {
		plan.RadiusProxyScheme = types.StringValue(updated.RadiusProxyScheme)
	}
	plan.RadiusProxyEnableForAcct = types.BoolValue(updated.RadiusProxyEnableForAcct)

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
