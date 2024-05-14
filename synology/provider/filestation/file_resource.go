package filestation

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	client "github.com/synology-community/synology-api/pkg"
	"github.com/synology-community/synology-api/pkg/api/filestation"
	"github.com/synology-community/synology-api/pkg/util/form"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &FileResource{}

func NewFileResource() resource.Resource {
	return &FileResource{}
}

type FileResource struct {
	client filestation.FileStationApi
}

// FileResourceModel describes the resource data model.
type FileResourceModel struct {
	Path          types.String `tfsdk:"path"`
	CreateParents types.Bool   `tfsdk:"create_parents"`
	Overwrite     types.Bool   `tfsdk:"overwrite"`
	Content       types.String `tfsdk:"content"`
	MD5           types.String `tfsdk:"md5"`
}

// Create implements resource.Resource.
func (f *FileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data FileResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	createParents := data.CreateParents.ValueBool()
	overwrite := data.Overwrite.ValueBool()
	path := data.Path.ValueString()
	fileContent := data.Content.ValueString()
	fileName := filepath.Base(data.Path.ValueString())
	fileDir := filepath.Dir(data.Path.ValueString())

	// Check if the file exists

	// If it exists, check the MD5 checksum

	// If the checksums match, return

	// Upload the file
	_, err := f.client.Upload(ctx, fileDir, form.File{
		Name:    fileName,
		Content: fileContent,
	}, createParents, overwrite)
	if err != nil {
		resp.Diagnostics.AddError("Failed to upload file", fmt.Sprintf("Unable to upload file, got error: %s", err))
		return
	}

	// Get the file's MD5 checksum
	md5, err := f.client.MD5(ctx, path)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("Unable to get file MD5, got error: %s", err))
		resp.Diagnostics.AddError("Failed to get file MD5", fmt.Sprintf("Unable to get file MD5, got error: %s", err))
		return
	}
	// Store the MD5 checksum in the state
	data.MD5 = types.StringValue(md5.MD5)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)

	// files, err := f.client.List(ctx, path)
	// if err != nil {
	// 	resp.Diagnostics.AddError("Failed to list files", fmt.Sprintf("Unable to list files, got error: %s", err))
	// 	return
	// }
	// for _, file := range files.Files {
	// 	if file.Name == fileName {

	// 	}
	// }
}

// Delete implements resource.Resource.
func (f *FileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data FileResourceModel
	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	path := data.Path.ValueString()
	// Start Delete the file
	_, err := f.client.Delete(ctx, []string{path}, true)

	if err != nil {
		if e := errors.Unwrap(err); e != nil {
			resp.Diagnostics.AddError("Failed to delete file", fmt.Sprintf("Unable to delete file, got error: %s", e))
		} else {
			resp.Diagnostics.AddError("Failed to delete file", fmt.Sprintf("Unable to delete file, got error: %s", err))
		}
		return
	}
}

// Read implements resource.Resource.
func (f *FileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data FileResourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	path := data.Path.ValueString()

	md5, err := f.client.MD5(ctx, path)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("Unable to get file MD5, got error: %s", err))
		resp.Diagnostics.AddError("Failed to get file MD5", fmt.Sprintf("Unable to get file MD5, got error: %s", err))
		return
	}

	if md5.MD5 != data.MD5.ValueString() {
		data.MD5 = types.StringValue(md5.MD5)

		resp.State.Set(ctx, &data)
	}
}

// Update implements resource.Resource.
func (f *FileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data FileResourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	path := data.Path.ValueString()
	fileName := filepath.Base(data.Path.ValueString())
	fileDir := filepath.Dir(data.Path.ValueString())

	// fileName := filepath.Join(data.Path.ValueString(), data.Name.ValueString())
	file := form.File{
		Name:    fileName,
		Content: data.Content.ValueString(),
	}

	// Check if the file exists

	// If it exists, check the MD5 checksum

	// If the checksums match, return

	// Upload the file
	_, err := f.client.Upload(
		ctx,
		fileDir,
		file, data.CreateParents.ValueBool(),
		true)
	if err != nil {
		resp.Diagnostics.AddError("Failed to upload file", fmt.Sprintf("Unable to upload file, got error: %s", err))
		return
	}

	// Get the file's MD5 checksum
	md5, err := f.client.MD5(ctx, path)
	if err != nil {
		tflog.Error(ctx, fmt.Sprintf("Unable to get file MD5, got error: %s", err))
		resp.Diagnostics.AddError("Failed to get file MD5", fmt.Sprintf("Unable to get file MD5, got error: %s", err))
		return
	}
	// Store the MD5 checksum in the state
	data.MD5 = types.StringValue(md5.MD5)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Metadata implements resource.Resource.
func (f *FileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = buildName(req.ProviderTypeName, "file")
}

// Schema implements resource.Resource.
func (f *FileResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "FileStation --- A file on the Synology NAS Filestation.",

		Attributes: map[string]schema.Attribute{
			"path": schema.StringAttribute{
				MarkdownDescription: "A destination folder path starting with a shared folder to which files can be uploaded.",
				Required:            true,
			},
			"content": schema.StringAttribute{
				MarkdownDescription: "A destination folder path starting with a shared folder to which files can be uploaded.",
				Required:            true,
			},
			"create_parents": schema.BoolAttribute{
				MarkdownDescription: "Create parent folder(s) if none exist.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"overwrite": schema.BoolAttribute{
				MarkdownDescription: "Overwrite the destination file if one exists.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"md5": schema.StringAttribute{
				MarkdownDescription: "The MD5 checksum of the file.",
				Computed:            true,
			},
		},
	}
}

func (f *FileResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(client.SynologyClient)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected client.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	f.client = client.FileStationAPI()
}
