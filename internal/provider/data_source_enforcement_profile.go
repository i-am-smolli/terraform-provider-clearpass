package provider

import (
	"context"
	"fmt"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &EnforcementProfileDataSource{}

func NewEnforcementProfileDataSource() datasource.DataSource {
	return &EnforcementProfileDataSource{}
}

// EnforcementProfileDataSource defines the data source implementation.
type EnforcementProfileDataSource struct {
	client client.ClientInterface
}

func (d *EnforcementProfileDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_enforcement_profile"
}

func (d *EnforcementProfileDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves the details of a specific Enforcement Profile in ClearPass by its ID or Name. " +
			"Enforcement profiles define the actions to be taken when a policy rule is matched, " +
			"such as returning RADIUS attributes, assigning a VLAN, or redirecting a user.",

		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "The numeric ID of the Enforcement Profile to retrieve. Must specify either `id` or `name`.",
			},
			"name": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The exact name of the Enforcement Profile to retrieve (e.g., 'Employee-Access-Profile'). Must specify either `id` or `name`.",
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("name")),
				},
			},
			"description": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Human-readable description of the Enforcement Profile.",
			},
			"type": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The type of enforcement profile (e.g., 'RADIUS', 'TACACS', 'Agent', 'Aruba_DUR').",
			},
			"action": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The action to take when the profile is applied (e.g., 'Accept', 'Reject', 'Drop'). Primarily used for RADIUS profiles.",
			},
			"device_group_list": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "A list of device groups associated with this profile.",
			},
			"agent_template": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Template for Agent enforcement profiles (e.g., 'Agent', 'AgentScript').",
			},
			"post_auth_template": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Template for Post-Authentication enforcement profiles (e.g., 'EntityUpdate', 'SessionRestriction', 'SessionNotify').",
			},
			"radius_dyn_authz_template": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Template for RADIUS Dynamic Authorization.",
			},
			"attributes": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "A list of attributes returned or applied by this profile.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The type or category of the attribute (e.g., 'Radius:IETF', 'Radius:Cisco').",
						},
						"name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The specific name of the attribute (e.g., 'Filter-Id', 'Tunnel-Type').",
						},
						"value": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The value assigned to the attribute.",
						},
					},
				},
			},
		},
	}
}

func (d *EnforcementProfileDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected client.ClientInterface, got: %T.", req.ProviderData))
		return
	}

	d.client = client
}

func (d *EnforcementProfileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data enforcementProfileModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var result *client.EnforcementProfileResult
	var err error

	if !data.ID.IsNull() && !data.ID.IsUnknown() {
		result, err = d.client.GetEnforcementProfile(ctx, int(data.ID.ValueInt64()))
	} else if !data.Name.IsNull() && !data.Name.IsUnknown() {
		result, err = d.client.GetEnforcementProfileByName(ctx, data.Name.ValueString())
	} else {
		resp.Diagnostics.AddError("Error", "Must provide either id or name")
		return
	}

	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read Enforcement Profile: %s", err))
		return
	}
	if result == nil {
		resp.Diagnostics.AddError("Error", "Enforcement Profile not found")
		return
	}

	data.ID = types.Int64Value(int64(result.ID))
	data.Name = types.StringValue(result.Name)
	data.Description = types.StringValue(result.Description)
	data.Type = types.StringValue(result.Type)
	data.Action = types.StringValue(result.Action)

	if result.AgentTemplate != "" {
		data.AgentTemplate = types.StringValue(result.AgentTemplate)
	} else {
		data.AgentTemplate = types.StringNull()
	}

	if result.PostAuthTemplate != "" {
		data.PostAuthTemplate = types.StringValue(result.PostAuthTemplate)
	} else {
		data.PostAuthTemplate = types.StringNull()
	}

	if result.RadiusDynAuthzTemplate != "" {
		data.RadiusDynAuthzTemplate = types.StringValue(result.RadiusDynAuthzTemplate)
	} else {
		data.RadiusDynAuthzTemplate = types.StringNull()
	}

	if result.DeviceGroupList != nil {
		deviceGroupsList, diags := types.ListValueFrom(ctx, types.StringType, result.DeviceGroupList)
		resp.Diagnostics.Append(diags...)
		data.DeviceGroupList = deviceGroupsList
	} else {
		data.DeviceGroupList = types.ListNull(types.StringType)
	}

	data.Attributes, _ = flattenProfileAttributes(ctx, result.Attributes)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
