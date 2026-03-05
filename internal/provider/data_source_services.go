package provider

import (
	"context"
	"fmt"
	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &servicesDataSource{}

type servicesDataSource struct {
	client client.ClientInterface
}

type servicesModel struct {
	Filter         types.String   `tfsdk:"filter"`
	Sort           types.String   `tfsdk:"sort"`
	Offset         types.Int64    `tfsdk:"offset"`
	Limit          types.Int64    `tfsdk:"limit"`
	CalculateCount types.Bool     `tfsdk:"calculate_count"`
	Services       []serviceModel `tfsdk:"services"`
}

func NewServicesDataSource() datasource.DataSource {
	return &servicesDataSource{}
}

func (d *servicesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_services"
}

func (d *servicesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *servicesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieve a list of ClearPass Services.",
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				MarkdownDescription: "JSON filter expression specifying the items to return.",
				Optional:            true,
			},
			"sort": schema.StringAttribute{
				MarkdownDescription: "Sort ordering for returned items (default +id).",
				Optional:            true,
			},
			"offset": schema.Int64Attribute{
				MarkdownDescription: "Zero based offset to start from.",
				Optional:            true,
			},
			"limit": schema.Int64Attribute{
				MarkdownDescription: "Maximum number of items to return (1 - 1000).",
				Optional:            true,
			},
			"calculate_count": schema.BoolAttribute{
				MarkdownDescription: "Whether to calculate the total item count.",
				Optional:            true,
			},
			"services": schema.ListNestedAttribute{
				MarkdownDescription: "List of services matching the query parameters.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							MarkdownDescription: "Numeric ID of the service.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "Name of the service.",
							Computed:            true,
						},
						"template": schema.StringAttribute{
							MarkdownDescription: "Template of the service.",
							Computed:            true,
						},
						"type": schema.StringAttribute{
							MarkdownDescription: "The type of service.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "Description of the service.",
							Computed:            true,
						},
						"enabled": schema.BoolAttribute{
							MarkdownDescription: "Whether the service is enabled.",
							Computed:            true,
						},
						"match_type": schema.StringAttribute{
							MarkdownDescription: "Specifies whether to match ALL or ANY of the service rules.",
							Computed:            true,
						},
						"service_rule": schema.ListNestedAttribute{
							MarkdownDescription: "A list of rules used to classify requests into this service.",
							Computed:            true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"type": schema.StringAttribute{
										MarkdownDescription: "The type of attribute to check.",
										Computed:            true,
									},
									"name": schema.StringAttribute{
										MarkdownDescription: "The name of the attribute to check.",
										Computed:            true,
									},
									"operator": schema.StringAttribute{
										MarkdownDescription: "The operator used for comparison.",
										Computed:            true,
									},
									"value": schema.StringAttribute{
										MarkdownDescription: "The value to compare against.",
										Computed:            true,
									},
								},
							},
						},
						"strip_username": schema.BoolAttribute{
							MarkdownDescription: "Strip Username",
							Computed:            true,
						},
						"auth_methods": schema.ListAttribute{
							MarkdownDescription: "A list of authentication methods allowed for this service.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"auth_sources": schema.ListAttribute{
							MarkdownDescription: "A list of authentication sources used to verify user credentials.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"role_mapping_policy": schema.StringAttribute{
							MarkdownDescription: "The name of the role mapping policy associated with this service.",
							Computed:            true,
						},
						"enforcement_policy": schema.StringAttribute{ // Using HCL name
							MarkdownDescription: "The name of the enforcement policy associated with this service.",
							Computed:            true,
						},
						"default_posture_token": schema.StringAttribute{
							MarkdownDescription: "Default Posture Token.",
							Computed:            true,
						},
						"posture_policies": schema.ListAttribute{
							MarkdownDescription: "List of Posture Policies.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"monitor_mode": schema.BoolAttribute{
							MarkdownDescription: "Enable to monitor network access without enforcement.",
							Computed:            true,
						},
						"strip_username_csv": schema.StringAttribute{
							MarkdownDescription: "Strip Username Rule (comma-separated).",
							Computed:            true,
						},
						"service_cert_cn": schema.StringAttribute{
							MarkdownDescription: "Subject DN of Service Certificate.",
							Computed:            true,
						},
						"use_cached_policy_results": schema.BoolAttribute{
							MarkdownDescription: "Enable to use cached Roles and Posture attributes from previous sessions.",
							Computed:            true,
						},
						"authz_sources": schema.ListAttribute{
							MarkdownDescription: "List of Additional authorization sources.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"posture_enabled": schema.BoolAttribute{
							MarkdownDescription: "Enable Posture Compliance.",
							Computed:            true,
						},
						"remediate_end_hosts": schema.BoolAttribute{
							MarkdownDescription: "Enable auto-remediation of non-compliant end-hosts.",
							Computed:            true,
						},
						"remediation_url": schema.StringAttribute{
							MarkdownDescription: "Remediation URL.",
							Computed:            true,
						},
						"audit_enabled": schema.BoolAttribute{
							MarkdownDescription: "Enable Audit End-hosts.",
							Computed:            true,
						},
						"audit_server": schema.StringAttribute{
							MarkdownDescription: "Audit Server Name.",
							Computed:            true,
						},
						"audit_trigger_condition": schema.StringAttribute{
							MarkdownDescription: "Audit Trigger Conditions (ALWAYS, NO_POSTURE, MAC_AUTH).",
							Computed:            true,
						},
						"audit_mac_auth_client_type": schema.StringAttribute{
							MarkdownDescription: "Client Type For MAC authentication request Audit Trigger Condition (KNOWN, UNKNOWN, BOTH).",
							Computed:            true,
						},
						"action_after_audit": schema.StringAttribute{
							MarkdownDescription: "Action after audit (NONE, SNMP, RADIUS).",
							Computed:            true,
						},
						"audit_coa_action": schema.StringAttribute{
							MarkdownDescription: "RADIUS CoA Action to be triggered after audit.",
							Computed:            true,
						},
						"profiler_enabled": schema.BoolAttribute{
							MarkdownDescription: "Enable Profile Endpoints.",
							Computed:            true,
						},
						"profiler_endpoint_classification": schema.ListAttribute{
							MarkdownDescription: "List of Endpoint classification(s) after which an action must be triggered.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"profiler_coa_action": schema.StringAttribute{
							MarkdownDescription: "RADIUS CoA Action to be triggered by Profiler.",
							Computed:            true,
						},
						"acct_proxy_enabled": schema.BoolAttribute{
							MarkdownDescription: "Enable Accounting Proxy Targets.",
							Computed:            true,
						},
						"acct_proxy_targets": schema.ListAttribute{
							MarkdownDescription: "List Accounting Proxy Target names.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"radius_proxy_scheme": schema.StringAttribute{
							MarkdownDescription: "Proxying Scheme for RADIUS Proxy Service Type (Load Balance, Failover).",
							Computed:            true,
						},
						"radius_proxy_targets": schema.ListAttribute{
							MarkdownDescription: "List of Proxy Targets for RADIUS Proxy Service Type.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"radius_proxy_enable_for_acct": schema.BoolAttribute{
							MarkdownDescription: "Enable proxy for accounting requests (Applicable only for RADIUS Proxy Service Type).",
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

func (d *servicesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state servicesModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var filter, sort *string
	var offset, limit *int
	var calcCount *bool

	if !state.Filter.IsNull() && !state.Filter.IsUnknown() {
		f := state.Filter.ValueString()
		filter = &f
	}
	if !state.Sort.IsNull() && !state.Sort.IsUnknown() {
		s := state.Sort.ValueString()
		sort = &s
	}
	if !state.Offset.IsNull() && !state.Offset.IsUnknown() {
		o := int(state.Offset.ValueInt64())
		offset = &o
	}
	if !state.Limit.IsNull() && !state.Limit.IsUnknown() {
		l := int(state.Limit.ValueInt64())
		limit = &l
	}
	if !state.CalculateCount.IsNull() && !state.CalculateCount.IsUnknown() {
		c := state.CalculateCount.ValueBool()
		calcCount = &c
	}

	serviceList, err := d.client.GetServices(ctx, filter, sort, offset, limit, calcCount)
	if err != nil {
		resp.Diagnostics.AddError("API Error", err.Error())
		return
	}

	state.Services = []serviceModel{}

	for _, service := range serviceList.Embedded.Items {
		sModel := serviceModel{
			ID:                       types.Int64Value(int64(service.ID)),
			Name:                     types.StringValue(service.Name),
			Type:                     types.StringValue(service.Type),
			Template:                 types.StringValue(service.Template),
			Description:              types.StringValue(service.Description),
			Enabled:                  types.BoolValue(service.Enabled),
			EnfPolicy:                types.StringValue(service.EnfPolicy), // Using EnfPolicy from API matched to enforcement_policy HCL
			RoleMappingPolicy:        types.StringValue(service.RoleMappingPolicy),
			StripUsername:            types.BoolValue(service.StripUsername),
			MatchType:                types.StringValue(service.RulesMatchType),
			DefaultPostureToken:      types.StringValue(service.DefaultPostureToken),
			MonitorMode:              types.BoolValue(service.MonitorMode),
			StripUsernameCSV:         types.StringValue(service.StripUsernameCSV),
			ServiceCertCN:            types.StringValue(service.ServiceCertCN),
			UseCachedPolicyResults:   types.BoolValue(service.UseCachedPolicyResults),
			PostureEnabled:           types.BoolValue(service.PostureEnabled),
			RemediateEndHosts:        types.BoolValue(service.RemediateEndHosts),
			RemediationURL:           types.StringValue(service.RemediationURL),
			AuditEnabled:             types.BoolValue(service.AuditEnabled),
			AuditServer:              types.StringValue(service.AuditServer),
			AuditTriggerCondition:    types.StringValue(service.AuditTriggerCondition),
			AuditMacAuthClientType:   types.StringValue(service.AuditMacAuthClientType),
			ActionAfterAudit:         types.StringValue(service.ActionAfterAudit),
			AuditCoaAction:           types.StringValue(service.AuditCoaAction),
			ProfilerEnabled:          types.BoolValue(service.ProfilerEnabled),
			ProfilerCoaAction:        types.StringValue(service.ProfilerCoaAction),
			AcctProxyEnabled:         types.BoolValue(service.AcctProxyEnabled),
			RadiusProxyScheme:        types.StringValue(service.RadiusProxyScheme),
			RadiusProxyEnableForAcct: types.BoolValue(service.RadiusProxyEnableForAcct),
		}

		sModel.AuthMethods, _ = types.ListValueFrom(ctx, types.StringType, service.AuthMethods)
		sModel.AuthSources, _ = types.ListValueFrom(ctx, types.StringType, service.AuthSources)
		sModel.PosturePolicies, _ = types.ListValueFrom(ctx, types.StringType, service.PosturePolicies)
		sModel.AuthzSources, _ = types.ListValueFrom(ctx, types.StringType, service.AuthzSources)
		sModel.ProfilerEndpointClassification, _ = types.ListValueFrom(ctx, types.StringType, service.ProfilerEndpointClassification)
		sModel.AcctProxyTargets, _ = types.ListValueFrom(ctx, types.StringType, service.AcctProxyTargets)
		sModel.RadiusProxyTargets, _ = types.ListValueFrom(ctx, types.StringType, service.RadiusProxyTargets)

		if service.Description == "" {
			sModel.Description = types.StringNull()
		}
		if service.Type == "" {
			sModel.Type = types.StringNull()
		}
		if service.RoleMappingPolicy == "" {
			sModel.RoleMappingPolicy = types.StringNull()
		}
		if service.DefaultPostureToken == "" {
			sModel.DefaultPostureToken = types.StringNull()
		}
		if service.StripUsernameCSV == "" {
			sModel.StripUsernameCSV = types.StringNull()
		}
		if service.ServiceCertCN == "" {
			sModel.ServiceCertCN = types.StringNull()
		}
		if service.RemediationURL == "" {
			sModel.RemediationURL = types.StringNull()
		}
		if service.AuditServer == "" {
			sModel.AuditServer = types.StringNull()
		}
		if service.AuditTriggerCondition == "" {
			sModel.AuditTriggerCondition = types.StringNull()
		}
		if service.AuditMacAuthClientType == "" {
			sModel.AuditMacAuthClientType = types.StringNull()
		}
		if service.ActionAfterAudit == "" {
			sModel.ActionAfterAudit = types.StringNull()
		}
		if service.AuditCoaAction == "" {
			sModel.AuditCoaAction = types.StringNull()
		}
		if service.ProfilerCoaAction == "" {
			sModel.ProfilerCoaAction = types.StringNull()
		}
		if service.RadiusProxyScheme == "" {
			sModel.RadiusProxyScheme = types.StringNull()
		}

		// Map Rules
		ruleElementType := map[string]attr.Type{
			"type":     types.StringType,
			"name":     types.StringType,
			"operator": types.StringType,
			"value":    types.StringType,
		}

		if len(service.RulesConditions) > 0 {
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
			sModel.ServiceRule, _ = types.ListValue(types.ObjectType{AttrTypes: ruleElementType}, ruleList)
		} else {
			sModel.ServiceRule, _ = types.ListValue(types.ObjectType{AttrTypes: ruleElementType}, []attr.Value{})
		}

		state.Services = append(state.Services, sModel)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
