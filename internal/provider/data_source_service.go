package provider

import (
	"context"
	"fmt"
	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &serviceDataSource{}

type serviceDataSource struct {
	client client.ClientInterface
}

func NewServiceDataSource() datasource.DataSource {
	return &serviceDataSource{}
}

func (d *serviceDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service"
}

func (d *serviceDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Type", fmt.Sprintf("Expected ClientInterface, got: %T", req.ProviderData))
		return
	}
	d.client = client
}

func (d *serviceDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Retrieve details of a single ClearPass Service by ID or Name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Numeric ID of the service.",
				Optional:    true,
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the service.",
				Optional:    true,
				Computed:    true,
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("name")),
				},
			},
			"template": schema.StringAttribute{
				Description: "The template used to create the service.",
				Computed:    true,
			},
			"type": schema.StringAttribute{
				Description: "The type of service.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the service.",
				Computed:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the service is enabled.",
				Computed:    true,
			},
			"match_type": schema.StringAttribute{
				Description: "Specifies whether to match ALL or ANY of the service rules.",
				Computed:    true,
			},
			"service_rule": schema.ListNestedAttribute{
				Description: "A list of rules used to classify requests into this service.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							Description: "The type of attribute to check.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The name of the attribute to check.",
							Computed:    true,
						},
						"operator": schema.StringAttribute{
							Description: "The operator used for comparison.",
							Computed:    true,
						},
						"value": schema.StringAttribute{
							Description: "The value to compare against.",
							Computed:    true,
						},
					},
				},
			},
			"strip_username": schema.BoolAttribute{
				Description: "Strip Username",
				Computed:    true,
			},
			"auth_methods": schema.ListAttribute{
				Description: "A list of authentication methods allowed for this service.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"auth_sources": schema.ListAttribute{
				Description: "A list of authentication sources used to verify user credentials.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"role_mapping_policy": schema.StringAttribute{
				Description: "The name of the role mapping policy associated with this service.",
				Computed:    true,
			},
			"enforcement_policy": schema.StringAttribute{
				Description: "The name of the enforcement policy associated with this service.",
				Computed:    true,
			},
			"default_posture_token": schema.StringAttribute{
				Description: "Default Posture Token.",
				Computed:    true,
			},
			"posture_policies": schema.ListAttribute{
				Description: "List of Posture Policies.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"monitor_mode": schema.BoolAttribute{
				Description: "Enable to monitor network access without enforcement.",
				Computed:    true,
			},
			"strip_username_csv": schema.StringAttribute{
				Description: "Strip Username Rule (comma-separated).",
				Computed:    true,
			},
			"service_cert_cn": schema.StringAttribute{
				Description: "Subject DN of Service Certificate.",
				Computed:    true,
			},
			"use_cached_policy_results": schema.BoolAttribute{
				Description: "Enable to use cached Roles and Posture attributes from previous sessions.",
				Computed:    true,
			},
			"authz_sources": schema.ListAttribute{
				Description: "List of Additional authorization sources.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"posture_enabled": schema.BoolAttribute{
				Description: "Enable Posture Compliance.",
				Computed:    true,
			},
			"remediate_end_hosts": schema.BoolAttribute{
				Description: "Enable auto-remediation of non-compliant end-hosts.",
				Computed:    true,
			},
			"remediation_url": schema.StringAttribute{
				Description: "Remediation URL.",
				Computed:    true,
			},
			"audit_enabled": schema.BoolAttribute{
				Description: "Enable Audit End-hosts.",
				Computed:    true,
			},
			"audit_server": schema.StringAttribute{
				Description: "Audit Server Name.",
				Computed:    true,
			},
			"audit_trigger_condition": schema.StringAttribute{
				Description: "Audit Trigger Conditions (ALWAYS, NO_POSTURE, MAC_AUTH).",
				Computed:    true,
			},
			"audit_mac_auth_client_type": schema.StringAttribute{
				Description: "Client Type For MAC authentication request Audit Trigger Condition (KNOWN, UNKNOWN, BOTH).",
				Computed:    true,
			},
			"action_after_audit": schema.StringAttribute{
				Description: "Action after audit (NONE, SNMP, RADIUS).",
				Computed:    true,
			},
			"audit_coa_action": schema.StringAttribute{
				Description: "RADIUS CoA Action to be triggered after audit.",
				Computed:    true,
			},
			"profiler_enabled": schema.BoolAttribute{
				Description: "Enable Profile Endpoints.",
				Computed:    true,
			},
			"profiler_endpoint_classification": schema.ListAttribute{
				Description: "List of Endpoint classification(s) after which an action must be triggered.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"profiler_coa_action": schema.StringAttribute{
				Description: "RADIUS CoA Action to be triggered by Profiler.",
				Computed:    true,
			},
			"acct_proxy_enabled": schema.BoolAttribute{
				Description: "Enable Accounting Proxy Targets.",
				Computed:    true,
			},
			"acct_proxy_targets": schema.ListAttribute{
				Description: "List Accounting Proxy Target names.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"radius_proxy_scheme": schema.StringAttribute{
				Description: "Proxying Scheme for RADIUS Proxy Service Type (Load Balance, Failover).",
				Computed:    true,
			},
			"radius_proxy_targets": schema.ListAttribute{
				Description: "List of Proxy Targets for RADIUS Proxy Service Type.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"radius_proxy_enable_for_acct": schema.BoolAttribute{
				Description: "Enable proxy for accounting requests (Applicable only for RADIUS Proxy Service Type).",
				Computed:    true,
			},
		},
	}
}

func (d *serviceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state serviceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var service *client.ServiceResult
	var err error

	if !state.ID.IsNull() && !state.ID.IsUnknown() {
		service, err = d.client.GetService(ctx, int(state.ID.ValueInt64()))
	} else if !state.Name.IsNull() && !state.Name.IsUnknown() {
		service, err = d.client.GetServiceByName(ctx, state.Name.ValueString())
	} else {
		resp.Diagnostics.AddError("Missing ID or Name", "Must provide either ID or Name for the service data source")
		return
	}

	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
		return
	}

	if service == nil {
		resp.Diagnostics.AddError("Not Found", "Service not found")
		return
	}

	state.ID = types.Int64Value(int64(service.ID))
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

	// Create nested slice for rules
	rules := make([]serviceRuleModel, len(service.RulesConditions))
	for i, r := range service.RulesConditions {
		rules[i] = serviceRuleModel{
			Type:     types.StringValue(r.Type),
			Name:     types.StringValue(r.Name),
			Operator: types.StringValue(r.Operator),
			Value:    types.StringValue(r.Value),
		}
	}
	listDiags := state.ServiceRule.ElementsAs(ctx, &rules, false)
	resp.Diagnostics.Append(listDiags...)

	// Note: Because we use 'ElementsAs' we only set the items temporarily.
	// But in TF plugin framework for data sources, we often have to build complex
	// attributes. So it's better to manually build a typed List. Let's fix that below.
	if len(service.RulesConditions) > 0 {
		ruleElementType := map[string]attr.Type{
			"type":     types.StringType,
			"name":     types.StringType,
			"operator": types.StringType,
			"value":    types.StringType,
		}

		var ruleList []attr.Value
		for _, r := range service.RulesConditions {
			ruleObj, _ := types.ObjectValue(ruleElementType, map[string]attr.Value{
				"type":     types.StringValue(r.Type),
				"name":     types.StringValue(r.Name),
				"operator": types.StringValue(r.Operator),
				"value":    types.StringValue(r.Value),
			})
			ruleList = append(ruleList, ruleObj)
		}

		state.ServiceRule, _ = types.ListValue(types.ObjectType{AttrTypes: ruleElementType}, ruleList)
	} else {
		// Needs correct empty list init
		ruleElementType := map[string]attr.Type{
			"type":     types.StringType,
			"name":     types.StringType,
			"operator": types.StringType,
			"value":    types.StringType,
		}
		state.ServiceRule, _ = types.ListValue(types.ObjectType{AttrTypes: ruleElementType}, []attr.Value{})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
