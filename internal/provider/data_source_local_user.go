package provider

import (
	"context"
	"fmt"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &LocalUserDataSource{}

func NewLocalUserDataSource() datasource.DataSource {
	return &LocalUserDataSource{}
}

type LocalUserDataSource struct {
	client client.ClientInterface
}

type LocalUserDataSourceModel struct {
	ID                 types.Int64  `tfsdk:"id"`
	UserID             types.String `tfsdk:"user_id"`
	Username           types.String `tfsdk:"username"`
	RoleName           types.String `tfsdk:"role_name"`
	Enabled            types.Bool   `tfsdk:"enabled"`
	PasswordHash       types.String `tfsdk:"password_hash"`
	PasswordNTLMHash   types.String `tfsdk:"password_ntlm_hash"`
	ChangePwdNextLogin types.Bool   `tfsdk:"change_pwd_next_login"`
	Attributes         types.Map    `tfsdk:"attributes"`
}

func (d *LocalUserDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_local_user"
}

func (d *LocalUserDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves information about a specific local user in ClearPass by its numeric ID.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				MarkdownDescription: "The numeric ID of the local user.",
				Required:            true,
			},
			"user_id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier for the user.",
				Computed:            true,
			},
			"username": schema.StringAttribute{
				MarkdownDescription: "The username used for authentication.",
				Computed:            true,
			},
			"role_name": schema.StringAttribute{
				MarkdownDescription: "The name of the role assigned to the user. This determines the user's permissions.",
				Computed:            true,
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the user account is enabled.",
				Computed:            true,
			},
			"password_hash": schema.StringAttribute{
				MarkdownDescription: "The password hash of the local user.",
				Computed:            true,
			},
			"password_ntlm_hash": schema.StringAttribute{
				MarkdownDescription: "The NTLM password hash of the local user.",
				Computed:            true,
			},
			"change_pwd_next_login": schema.BoolAttribute{
				MarkdownDescription: "Flag indicating if the password change is required in next login.",
				Computed:            true,
			},
			"attributes": schema.MapAttribute{
				MarkdownDescription: "Additional attributes (key/value pairs) stored with the local user account.",
				Computed:            true,
				ElementType:         types.StringType,
			},
		},
	}
}

func (d *LocalUserDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *LocalUserDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data LocalUserDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	numericID := data.ID.ValueInt64()

	user, err := d.client.GetLocalUser(ctx, int(numericID))
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read local user: %s", err))
		return
	}

	if user == nil {
		resp.Diagnostics.AddError("Not Found", fmt.Sprintf("Local user with ID %d not found", numericID))
		return
	}

	data.ID = types.Int64Value(int64(user.ID))
	data.UserID = types.StringValue(user.UserID)
	data.Username = types.StringValue(user.Username)
	data.RoleName = types.StringValue(user.RoleName)
	data.Enabled = types.BoolValue(user.Enabled)
	data.PasswordHash = types.StringValue(user.PasswordHash)
	data.PasswordNTLMHash = types.StringValue(user.PasswordNTLMHash)
	data.ChangePwdNextLogin = types.BoolValue(user.ChangePwdNextLogin)

	if len(user.Attributes) > 0 {
		attrs, diag := types.MapValueFrom(ctx, types.StringType, user.Attributes)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.Attributes = attrs
	} else {
		data.Attributes = types.MapNull(types.StringType)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
