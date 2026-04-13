package provider

import (
	"context"
	"fmt"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &extensionInstancesDataSource{}

type extensionInstancesDataSource struct {
	client client.ClientInterface
}

type extensionInstancesDataSourceModel struct {
	Instances []extensionInstanceDataItem `tfsdk:"instances"`
}

type extensionInstanceDataItem struct {
	ID               types.String `tfsdk:"id"`
	State            types.String `tfsdk:"state"`
	StateDetails     types.String `tfsdk:"state_details"`
	StoreID          types.String `tfsdk:"store_id"`
	Name             types.String `tfsdk:"name"`
	Version          types.String `tfsdk:"version"`
	Description      types.String `tfsdk:"description"`
	IconHref         types.String `tfsdk:"icon_href"`
	AboutHref        types.String `tfsdk:"about_href"`
	Hostname         types.String `tfsdk:"hostname"`
	InternalIPAddr   types.String `tfsdk:"internal_ip_address"`
	NeedsReinstall   types.Bool   `tfsdk:"needs_reinstall"`
	ReinstallDetails types.String `tfsdk:"reinstall_details"`
	HasConfig        types.Bool   `tfsdk:"has_config"`
	InstallTime      types.String `tfsdk:"install_time"`
	Note             types.String `tfsdk:"note"`
	Upgrade          types.String `tfsdk:"upgrade"`
}

func NewExtensionInstancesDataSource() datasource.DataSource {
	return &extensionInstancesDataSource{}
}

func (d *extensionInstancesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_extension_instances"
}

func (d *extensionInstancesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a list of all ClearPass Extension Instances.",
		Attributes: map[string]schema.Attribute{
			"instances": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "List of extension instances",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "ID of the extension instance",
						},
						"state": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Current state of the extension",
						},
						"state_details": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Additional information about the current state",
						},
						"store_id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "ID of the extension in the store",
						},
						"name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Name of the extension",
						},
						"version": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Version number of the extension",
						},
						"description": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Description of the extension",
						},
						"icon_href": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "URL for the extension's icon",
						},
						"about_href": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "URL for the extension's documentation",
						},
						"hostname": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Hostname assigned to the extension",
						},
						"internal_ip_address": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Internal IP address of the extension",
						},
						"needs_reinstall": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Indicates if the extension is out-of-date",
						},
						"reinstall_details": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Reinstall operation details",
						},
						"has_config": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Extension has configuration settings",
						},
						"install_time": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Installation time",
						},
						"note": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "User note about the extension",
						},
						"upgrade": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Available upgrade information",
						},
					},
				},
			},
		},
	}
}

func (d *extensionInstancesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected DataSource Configure Type",
			fmt.Sprintf("Expected client.ClientInterface, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

func (d *extensionInstancesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data extensionInstancesDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	extList, err := d.client.GetExtensionInstances(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read extension instances", err.Error())
		return
	}

	if extList == nil || len(extList.Embedded.Items) == 0 {
		data.Instances = []extensionInstanceDataItem{}
	} else {
		data.Instances = make([]extensionInstanceDataItem, 0, len(extList.Embedded.Items))
		for _, ext := range extList.Embedded.Items {
			item := extensionInstanceDataItem{}
			d.apiResultToModel(&ext, &item)
			data.Instances = append(data.Instances, item)
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *extensionInstancesDataSource) apiResultToModel(apiResult *client.ExtensionInstanceResult, model *extensionInstanceDataItem) {
	model.ID = types.StringValue(apiResult.ID)
	model.State = types.StringValue(apiResult.State)
	model.StateDetails = types.StringValue(apiResult.StateDetails)
	model.StoreID = types.StringValue(apiResult.StoreID)
	model.Name = types.StringValue(apiResult.Name)
	model.Version = types.StringValue(apiResult.Version)
	model.Description = types.StringValue(apiResult.Description)
	model.IconHref = types.StringValue(apiResult.IconHref)
	model.AboutHref = types.StringValue(apiResult.AboutHref)
	model.Hostname = types.StringValue(apiResult.Hostname)
	model.InternalIPAddr = types.StringValue(apiResult.InternalIPAddr)
	model.NeedsReinstall = types.BoolValue(apiResult.NeedsReinstall)
	model.ReinstallDetails = types.StringValue(apiResult.ReinstallDetails)
	model.HasConfig = types.BoolValue(apiResult.HasConfig)
	model.InstallTime = types.StringValue(apiResult.InstallTime)
	model.Note = types.StringValue(apiResult.Note)
	model.Upgrade = types.StringValue(apiResult.Upgrade)
}
