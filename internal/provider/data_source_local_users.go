package provider

import (
	"context"
	"fmt"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &LocalUsersDataSource{}

func NewLocalUsersDataSource() datasource.DataSource {
	return &LocalUsersDataSource{}
}

type LocalUsersDataSource struct {
	client client.ClientInterface
}

type LocalUsersDataSourceModel struct {
	ID    types.String                        `tfsdk:"id"`
	Items []LocalUsersListItemDataSourceModel `tfsdk:"items"`
}

type LocalUsersListItemDataSourceModel struct {
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

func (d *LocalUsersDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_local_users"
}

func (d *LocalUsersDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a comprehensive list of all Local Users available in ClearPass.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Placeholder identifier to satisfy Terraform framework requirements.",
				Computed:            true,
			},
		},
		Blocks: map[string]schema.Block{
			"items": schema.ListNestedBlock{
				MarkdownDescription: "A list containing the local users and their basic summary information.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							MarkdownDescription: "The numeric ID of the local user.",
							Computed:            true,
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
				},
			},
		},
	}
}

func (d *LocalUsersDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *LocalUsersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data LocalUsersDataSourceModel

	result, err := d.client.GetLocalUsers(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read local users: %s", err))
		return
	}

	data.ID = types.StringValue("placeholder")

	for _, item := range result.Embedded.Items {
		itemModel := LocalUsersListItemDataSourceModel{
			ID:                 types.Int64Value(int64(item.ID)),
			UserID:             types.StringValue(item.UserID),
			Username:           types.StringValue(item.Username),
			RoleName:           types.StringValue(item.RoleName),
			Enabled:            types.BoolValue(item.Enabled),
			PasswordHash:       types.StringValue(item.PasswordHash),
			PasswordNTLMHash:   types.StringValue(item.PasswordNTLMHash),
			ChangePwdNextLogin: types.BoolValue(item.ChangePwdNextLogin),
		}

		if len(item.Attributes) > 0 {
			attrs, diag := types.MapValueFrom(ctx, types.StringType, item.Attributes)
			resp.Diagnostics.Append(diag...)
			if resp.Diagnostics.HasError() {
				return
			}
			itemModel.Attributes = attrs
		} else {
			itemModel.Attributes = types.MapNull(types.StringType)
		}

		data.Items = append(data.Items, itemModel)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
