package provider

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/appkins/terraform-provider-synology/synology/provider/container"
	"github.com/appkins/terraform-provider-synology/synology/provider/core"
	"github.com/appkins/terraform-provider-synology/synology/provider/filestation"
	"github.com/appkins/terraform-provider-synology/synology/provider/virtualization"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	client "github.com/synology-community/go-synology"
	"github.com/synology-community/go-synology/pkg/api"
)

const (
	SYNOLOGY_HOST_ENV_VAR            = "SYNOLOGY_HOST"
	SYNOLOGY_USER_ENV_VAR            = "SYNOLOGY_USER"
	SYNOLOGY_PASSWORD_ENV_VAR        = "SYNOLOGY_PASSWORD"
	SYNOLOGY_OTP_SECRET_ENV_VAR      = "SYNOLOGY_OTP_SECRET"
	SYNOLOGY_SKIP_CERT_CHECK_ENV_VAR = "SYNOLOGY_SKIP_CERT_CHECK"
)

var (
	// Regex to match IP address with optional port
	ipRegex = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}(:\d+)?$`)
)

// SynologyProvider defines the provider implementation.
type SynologyProvider struct{}

// SynologyProviderModel describes the provider data model.
type SynologyProviderModel struct {
	Host          types.String `tfsdk:"host"`
	User          types.String `tfsdk:"user"`
	Password      types.String `tfsdk:"password"`
	OtpSecret     types.String `tfsdk:"otp_secret"`
	SkipCertCheck types.Bool   `tfsdk:"skip_cert_check"`
}

func (p *SynologyProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "synology"
	tflog.Info(ctx, "Starting Synology Provider")
}

func (p *SynologyProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Description: "Remote Synology station host, IP, or IP:port.",
				Optional:    true,
			},
			"user": schema.StringAttribute{
				Description: "User to connect to Synology station with.",
				Optional:    true,
			},
			"password": schema.StringAttribute{
				Description: "Password to use when connecting to Synology station.",
				Optional:    true,
				Sensitive:   true,
			},
			"otp_secret": schema.StringAttribute{
				Description: "OTP secret to use when connecting to Synology station.",
				Optional:    true,
				Sensitive:   true,
			},
			"skip_cert_check": schema.BoolAttribute{
				Description: "Whether to skip SSL certificate checks.",
				Optional:    true,
			},
		},
	}
}

func (p *SynologyProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data SynologyProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	host := data.Host.ValueString()
	if host == "" {
		if v := os.Getenv(SYNOLOGY_HOST_ENV_VAR); v != "" {
			host = v
		}
	}

	// Validate and format the host
	host, err := formatHost(host)
	if err != nil {
		resp.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
			path.Root("host"),
			"Invalid provider configuration",
			fmt.Sprintf("Invalid host format: %s", err),
		))
		return
	}

	user := data.User.ValueString()
	if user == "" {
		if v := os.Getenv(SYNOLOGY_USER_ENV_VAR); v != "" {
			user = v
		}
	}
	password := data.Password.ValueString()
	if password == "" {
		if v := os.Getenv(SYNOLOGY_PASSWORD_ENV_VAR); v != "" {
			password = v
		}
	}
	otpSecret := data.OtpSecret.ValueString()
	if otpSecret == "" {
		if v := os.Getenv(SYNOLOGY_OTP_SECRET_ENV_VAR); v != "" {
			otpSecret = v
		}
	}

	skipCertCheck := data.SkipCertCheck.ValueBool()
	if v := os.Getenv(SYNOLOGY_SKIP_CERT_CHECK_ENV_VAR); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			skipCertCheck = parsed
		}
	}

	c, err := client.New(api.Options{
		Host:       host,
		VerifyCert: !skipCertCheck,
	})
	if err != nil {
		resp.Diagnostics.Append(diag.NewErrorDiagnostic("Synology client creation failed", fmt.Sprintf("Unable to create Synology client, got error: %v", err)))
		return
	}

	if _, err := c.Login(ctx, user, password, otpSecret); err != nil {
		resp.Diagnostics.Append(diag.NewErrorDiagnostic("Login to Synology station failed", fmt.Sprintf("Unable to login to Synology station, got error: %s", err)))
	}

	resp.DataSourceData = c
	resp.ResourceData = c
}

// formatHost validates and formats the host value.
func formatHost(host string) (string, error) {
	// Check if it's a valid IP with optional port
	if ipRegex.MatchString(host) {
		if !strings.Contains(host, ":") {
			// Add default port if no port specified
			host = host + ":5000"
		}
		return "http://" + host, nil
	}

	// Attempt to parse as a URL
	parsedURL, err := url.Parse(host)
	if err == nil && parsedURL.Scheme != "" && parsedURL.Host != "" {
		return host, nil
	}

	// Attempt to resolve as a hostname
	if _, err := net.LookupHost(host); err == nil {
		return "http://" + host, nil
	}

	return "", fmt.Errorf("host must be a valid IP, hostname, or URL")
}

func (p *SynologyProvider) ValidateConfig(ctx context.Context, req provider.ValidateConfigRequest, resp *provider.ValidateConfigResponse) {
	var data SynologyProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	host := data.Host.ValueString()
	if _, err := formatHost(host); err != nil {
		resp.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
			path.Root("host"),
			"Invalid provider configuration",
			"Host must be a valid IP, hostname, or URL with an optional port (default port 5000 will be used if none specified)",
		))
	}
}
