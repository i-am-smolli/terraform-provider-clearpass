package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"terraform-provider-clearpass/internal/client"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &adminPrivilegesDataSource{}
	_ datasource.DataSourceWithConfigure = &adminPrivilegesDataSource{}
)

// NewAdminPrivilegesDataSource is a helper function to simplify the provider implementation.
func NewAdminPrivilegesDataSource() datasource.DataSource {
	return &adminPrivilegesDataSource{}
}

// adminPrivilegesDataSource is the data source implementation.
type adminPrivilegesDataSource struct {
	client client.ClientInterface
}

// adminPrivilegesDataSourceModel maps the data source schema data.
type adminPrivilegesDataSourceModel struct {
	Filter          types.String                `tfsdk:"filter"`
	AdminPrivileges []adminPrivilegesModelItems `tfsdk:"admin_privileges"`
}

// adminPrivilegesModelItems maps the items in the admin privileges list.
type adminPrivilegesModelItems struct {
	ID                   types.Int64  `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	Description          types.String `tfsdk:"description"`
	AccessType           types.String `tfsdk:"access_type"`
	CppmPrivileges       types.Map    `tfsdk:"cppm_privileges"`
	InsightPrivileges    types.Map    `tfsdk:"insight_privileges"`
	AllowPasswords       types.Bool   `tfsdk:"allow_passwords"`
	AllowSecurityConfigs types.Bool   `tfsdk:"allow_security_configs"`
}

// Metadata returns the data source type name.
func (d *adminPrivilegesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_admin_privileges"
}

// Schema defines the schema for the data source.
func (d *adminPrivilegesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a list of ClearPass admin privileges, optionally filtered using a JSON filter expression.",
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				MarkdownDescription: "JSON filter expression to narrow results.",
				Optional:            true,
			},
			"admin_privileges": schema.ListNestedAttribute{
				MarkdownDescription: "List of admin privileges matching the filter.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							MarkdownDescription: "Numeric ID of the admin privilege.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "Name of the admin privilege.",
							Computed:            true,
						},
						"description": schema.StringAttribute{
							MarkdownDescription: "Description of the admin privilege.",
							Computed:            true,
						},
						"access_type": schema.StringAttribute{
							MarkdownDescription: "Access type of the admin privilege.",
							Computed:            true,
						},
						"cppm_privileges": schema.MapAttribute{
							MarkdownDescription: "Privilege list for ClearPass Policy Manager.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"insight_privileges": schema.MapAttribute{
							MarkdownDescription: "Privilege list for ClearPass Insight.",
							Computed:            true,
							ElementType:         types.StringType,
						},
						"allow_passwords": schema.BoolAttribute{
							MarkdownDescription: "Whether passwords may be displayed in responses.",
							Computed:            true,
						},
						"allow_security_configs": schema.BoolAttribute{
							MarkdownDescription: "Whether the user has access to security configuration.",
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *adminPrivilegesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected client.ClientInterface, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

// Read refreshes the Terraform state with the latest data.
func (d *adminPrivilegesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state adminPrivilegesDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var filter *string
	if !state.Filter.IsNull() {
		f := state.Filter.ValueString()
		filter = &f
	}

	limit := 1000
	results, err := d.client.GetAdminPrivileges(ctx, filter, nil, nil, &limit, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading ClearPass Admin Privileges",
			"Could not read ClearPass admin privileges: "+err.Error(),
		)
		return
	}

	state.AdminPrivileges = []adminPrivilegesModelItems{}
	if results != nil {
		for _, item := range results.Embedded.Items {
			cppmVal := types.MapNull(types.StringType)
			if len(item.CppmPrivileges) > 0 {
				cMap, diag := types.MapValueFrom(ctx, types.StringType, item.CppmPrivileges)
				resp.Diagnostics.Append(diag...)
				if resp.Diagnostics.HasError() {
					return
				}
				cppmVal = cMap
			}

			insightVal := types.MapNull(types.StringType)
			if len(item.InsightPrivileges) > 0 {
				iMap, diag := types.MapValueFrom(ctx, types.StringType, item.InsightPrivileges)
				resp.Diagnostics.Append(diag...)
				if resp.Diagnostics.HasError() {
					return
				}
				insightVal = iMap
			}

			state.AdminPrivileges = append(state.AdminPrivileges, adminPrivilegesModelItems{
				ID:                   types.Int64Value(int64(item.ID)),
				Name:                 types.StringValue(item.Name),
				Description:          types.StringValue(item.Description),
				AccessType:           types.StringValue(item.AccessType),
				CppmPrivileges:       cppmVal,
				InsightPrivileges:    insightVal,
				AllowPasswords:       types.BoolValue(item.AllowPasswords),
				AllowSecurityConfigs: types.BoolValue(item.AllowSecurityConfigs),
			})
		}
	}

	// Set state
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
