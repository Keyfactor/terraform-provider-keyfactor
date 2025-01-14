package keyfactor

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	"github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var stderr = os.Stderr

func New() tfsdk.Provider {
	return &provider{}
}

type provider struct {
	configured bool
	client     *api.Client
}

const (
	EnvVarUsage              = "This can also be set via the `%s` environment variable."
	DefaultValMsg            = "Default value is `%v`."
	InvalidProviderConfigErr = "invalid provider configuration"
)

// GetSchema - Defines provider schema
func (p *provider) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	fmt.Sprintf("%s", auth_providers.EnvKeyfactorHostName)
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"hostname": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Hostname of Keyfactor Command instance. Ex: keyfactor.examplecompany.com. "+
						EnvVarUsage, auth_providers.EnvKeyfactorHostName,
				),
			},
			"command_ca_certificate": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Path to CA certificate to use when connecting to the Keyfactor Command API in PEM"+
						" format."+EnvVarUsage, auth_providers.EnvKeyfactorCACert,
				),
			},
			"auth_ca_certificate": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Path to CA certificate to use when connecting to a Keyfactor Command identity provider in PEM"+
						" format."+EnvVarUsage, auth_providers.EnvKeyfactorCACert,
				),
			},
			"api_path": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Path to Keyfactor Command API."+DefaultValMsg+EnvVarUsage,
					auth_providers.DefaultCommandAPIPath, auth_providers.EnvKeyfactorAPIPath,
				),
			},
			"username": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Username of Keyfactor Command service account. "+
						EnvVarUsage, auth_providers.EnvKeyfactorUsername,
				),
			},
			"password": {
				Type:      types.StringType,
				Optional:  true,
				Sensitive: true,
				Description: fmt.Sprintf(
					"Password of Keyfactor Command service account. "+
						EnvVarUsage, auth_providers.EnvKeyfactorPassword,
				),
			},
			"appkey": {
				Type:      types.StringType,
				Optional:  true,
				Sensitive: true,
				Description: "Application key provisioned by Keyfactor Command instance." +
					"This can also be set via the `KEYFACTOR_APPKEY` environment variable.",
			},
			"domain": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Domain that Keyfactor Command instance is hosted on. "+
						EnvVarUsage, auth_providers.EnvKeyfactorDomain,
				),
			},
			"token_url": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"OAuth token URL for Keyfactor Command instance. "+
						EnvVarUsage, auth_providers.EnvKeyfactorAuthTokenURL,
				),
			},
			"client_id": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"Client ID for OAuth authentication. "+EnvVarUsage, auth_providers.EnvKeyfactorClientID,
				),
			},
			"client_secret": {
				Type:      types.StringType,
				Optional:  true,
				Sensitive: true,
				Description: fmt.Sprintf(
					"Client secret for OAuth authentication. "+EnvVarUsage, auth_providers.EnvKeyfactorClientSecret,
				),
			},
			"access_token": {
				Type:      types.StringType,
				Optional:  true,
				Sensitive: true,
				Description: fmt.Sprintf(
					"Access token for OAuth authentication. "+EnvVarUsage, auth_providers.EnvKeyfactorAccessToken,
				),
			},
			"scopes": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"A list of comma separated OAuth scopes to request when authenticating. "+
						EnvVarUsage, auth_providers.EnvKeyfactorAuthScopes,
				),
			},
			"audience": {
				Type:     types.StringType,
				Optional: true,
				Description: fmt.Sprintf(
					"OAuth audience to request when authenticating. "+
						EnvVarUsage, auth_providers.EnvKeyfactorAuthAudience,
				),
			},
			"request_timeout": {
				Type:     types.Int64Type,
				Optional: true,
				Description: fmt.Sprintf(
					"Global timeout for HTTP requests to Keyfactor Command instance. "+EnvVarUsage+DefaultValMsg,
					auth_providers.EnvKeyfactorClientTimeout, auth_providers.DefaultClientTimeout,
				),
			},
			"skip_tls_verify": {
				Type:     types.BoolType,
				Optional: true,
				Description: fmt.Sprintf(
					"Skip TLS verification when connecting to Keyfactor Command API and identity provider."+
						DefaultValMsg+EnvVarUsage, false, auth_providers.EnvKeyfactorSkipVerify,
				),
			},
		},
	}, nil
}

// Provider schema struct
type providerData struct {
	Username             types.String `tfsdk:"username"`
	Hostname             types.String `tfsdk:"hostname"`
	CommandCACertificate types.String `tfsdk:"command_ca_certificate"`
	AuthCACertificate    types.String `tfsdk:"auth_ca_certificate"`
	Password             types.String `tfsdk:"password"`
	ApiKey               types.String `tfsdk:"appkey"`
	ApiPath              types.String `tfsdk:"api_path"`
	Domain               types.String `tfsdk:"domain"`
	TokenURL             types.String `tfsdk:"token_url"`
	ClientID             types.String `tfsdk:"client_id"`
	ClientSecret         types.String `tfsdk:"client_secret"`
	AccessToken          types.String `tfsdk:"access_token"`
	Scopes               types.String `tfsdk:"scopes"`
	Audience             types.String `tfsdk:"audience"`
	RequestTimeout       types.Int64  `tfsdk:"request_timeout"`
	SkipTLSVerify        types.Bool   `tfsdk:"skip_tls_verify"`
}

func (p *provider) getServerConfig(c *providerData, ctx context.Context) (*auth_providers.Server, diag.Diagnostics) {

	oAuthNoParamsConfig := &auth_providers.CommandConfigOauth{}
	basicAuthNoParamsConfig := &auth_providers.CommandAuthConfigBasic{}
	d := diag.Diagnostics{}

	// Core provider config
	hostname, hOk := os.LookupEnv(auth_providers.EnvKeyfactorHostName)
	if !hOk && c.Hostname.Value != "" {
		hostname = c.Hostname.Value
		hOk = true
	}
	apiPath, aOk := os.LookupEnv(auth_providers.EnvKeyfactorAPIPath)
	if !aOk && c.ApiPath.Value != "" {
		apiPath = c.ApiPath.Value
	}

	skipVerify, svOk := os.LookupEnv(auth_providers.EnvKeyfactorSkipVerify)
	var skipVerifyBool bool

	if c.SkipTLSVerify.Value {
		skipVerifyBool = true
	} else if svOk {
		//convert to bool
		skipVerify = strings.ToLower(skipVerify)
		skipVerifyBool = skipVerify == "true" || skipVerify == "1" || skipVerify == "yes" || skipVerify == "y" || skipVerify == "t"
	}

	clientTimeoutStr, tOk := os.LookupEnv(auth_providers.EnvKeyfactorClientTimeout)
	var clientTimeout int64
	if !tOk && c.RequestTimeout.Value != 0 {
		clientTimeout = c.RequestTimeout.Value
	} else if tOk {
		clientTimeout, _ = strconv.ParseInt(clientTimeoutStr, 10, 64)
	}
	if clientTimeout <= 0 {
		tflog.Warn(
			ctx, fmt.Sprintf(
				"invalid value for `client_timeout` using default of %d",
				auth_providers.DefaultClientTimeout,
			),
		)
		clientTimeout = auth_providers.DefaultClientTimeout
	}

	caCert, caOk := os.LookupEnv(auth_providers.EnvKeyfactorCACert)
	if !caOk && c.CommandCACertificate.Value != "" {
		caCert = c.CommandCACertificate.Value
	}

	// Basic auth provider config
	username, uOk := os.LookupEnv(auth_providers.EnvKeyfactorUsername)
	if !uOk && c.Username.Value != "" {
		username = c.Username.Value
		uOk = true
	}
	password, pOk := os.LookupEnv(auth_providers.EnvKeyfactorPassword)
	if !pOk && c.Password.Value != "" {
		password = c.Password.Value
		pOk = true
	}
	domain, dOk := os.LookupEnv(auth_providers.EnvKeyfactorDomain)
	if !dOk && c.Domain.Value != "" {
		domain = c.Domain.Value
		dOk = true
	}

	//oAuth auth provider config
	clientId, cOk := os.LookupEnv(auth_providers.EnvKeyfactorClientID)
	if !cOk && c.ClientID.Value != "" {
		clientId = c.ClientID.Value
	}
	clientSecret, csOk := os.LookupEnv(auth_providers.EnvKeyfactorClientSecret)
	if !cOk && c.ClientSecret.Value != "" {
		clientSecret = c.ClientSecret.Value
	}
	tokenUrl, tOk := os.LookupEnv(auth_providers.EnvKeyfactorAuthTokenURL)
	if !tOk && c.TokenURL.Value != "" {
		tokenUrl = c.TokenURL.Value
		tOk = true
	}
	accessToken, atOk := os.LookupEnv(auth_providers.EnvKeyfactorAccessToken)
	if !atOk && c.AccessToken.Value != "" {
		accessToken = c.AccessToken.Value
		atOk = true
	}

	isBasicAuth := uOk && pOk
	isOAuth := (cOk && csOk && tOk) || atOk

	if isBasicAuth {
		tflog.Debug(ctx, "call: basicAuthNoParamsConfig.Authenticate()")
		basicAuthNoParamsConfig.WithCommandHostName(hostname).
			WithCommandAPIPath(apiPath).
			WithSkipVerify(skipVerifyBool).
			WithCommandCACert(caCert).
			WithClientTimeout(int(clientTimeout))
		bErr := basicAuthNoParamsConfig.
			WithUsername(username).
			WithPassword(password).
			WithDomain(domain).
			Authenticate()

		tflog.Debug(ctx, "complete: basicAuthNoParamsConfig.Authenticate()")
		if bErr != nil {
			errMsg := "unable to authenticate with provided basic auth credentials"
			tflog.Error(ctx, errMsg)
			d.AddError("basic auth authentication error", errMsg)
			return nil, d
		}
		tflog.Debug(ctx, "return: getServerConfigFromEnv()")
		return basicAuthNoParamsConfig.GetServerConfig(), d
	} else if isOAuth {
		tflog.Debug(ctx, "call: oAuthNoParamsConfig.Authenticate()")
		_ = oAuthNoParamsConfig.CommandAuthConfig.
			WithCommandHostName(hostname).
			WithCommandAPIPath(apiPath).
			WithSkipVerify(skipVerifyBool).
			WithCommandCACert(caCert).
			WithClientTimeout(int(clientTimeout))
		oErr := oAuthNoParamsConfig.
			WithClientId(clientId).
			WithClientSecret(clientSecret).
			WithTokenUrl(tokenUrl).
			WithAccessToken(accessToken).
			Authenticate()
		tflog.Debug(ctx, "complete: oAuthNoParamsConfig.Authenticate()")
		if oErr != nil {
			oErrMsg := "unable to authenticate with provided OAuth auth credentials"
			tflog.Error(ctx, oErrMsg)
			d.AddError("oauth authentication error: "+oErr.Error(), oErrMsg)
			return nil, d
		}

		tflog.Debug(ctx, "return: getServerConfigFromEnv()")
		return oAuthNoParamsConfig.GetServerConfig(), d
	}

	cErrMsg := "unable to authenticate with provided credentials"
	tflog.Error(ctx, cErrMsg)
	d.AddError("client configuration error", cErrMsg)
	return nil, d

}

func (p *provider) Configure(
	ctx context.Context,
	req tfsdk.ConfigureProviderRequest,
	resp *tfsdk.ConfigureProviderResponse,
) {
	// Retrieve provider data from configuration
	var config providerData

	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "validating provider auth configuration")
	serverConfig, confDiags := p.getServerConfig(&config, ctx)
	resp.Diagnostics.Append(confDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, "provider configuration is valid")

	// User must provide a user to the provider
	connected := false
	connectionRetries := 0
	for !connected && connectionRetries < 5 {
		c, err := api.NewKeyfactorClient(serverConfig, &ctx)

		if err != nil {
			if connectionRetries == 4 {
				resp.Diagnostics.AddError(
					"Client error.",
					"Unable to create client connection to Keyfactor Command:\n\n"+err.Error(),
				)
				return
			}
			connectionRetries++
			// Sleep for 5 seconds before retrying
			time.Sleep(5 * time.Second)
			continue
		}
		connected = true
		p.client = c
		p.configured = true
		return
	}
}

// GetResources - Defines provider resources
func (p *provider) GetResources(_ context.Context) (map[string]tfsdk.ResourceType, diag.Diagnostics) {
	return map[string]tfsdk.ResourceType{
		"keyfactor_identity":               resourceSecurityIdentityType{},
		"keyfactor_certificate":            resourceKeyfactorCertificateType{},
		"keyfactor_certificate_store":      resourceCertificateStoreType{},
		"keyfactor_certificate_deployment": resourceKeyfactorCertificateDeploymentType{},
		"keyfactor_role":                   resourceSecurityRoleType{},
		"keyfactor_template_role_binding":  resourceCertificateTemplateRoleBindingType{},
	}, nil
}

// GetDataSources - Defines provider data sources
func (p *provider) GetDataSources(_ context.Context) (map[string]tfsdk.DataSourceType, diag.Diagnostics) {
	return map[string]tfsdk.DataSourceType{
		"keyfactor_agent":                dataSourceAgentType{},
		"keyfactor_certificate":          dataSourceCertificateType{},
		"keyfactor_certificate_store":    dataSourceCertificateStoreType{},
		"keyfactor_certificate_template": dataSourceCertificateTemplateType{},
		"keyfactor_role":                 dataSourceSecurityRoleType{},
		"keyfactor_identity":             dataSourceSecurityIdentityType{},
	}, nil
}

// // Utility functions
func boolToPointer(b bool) *bool {
	return &b
}

func intToPointer(i int) *int {
	if i == 0 {
		return nil
	}
	return &i
}

func stringToPointer(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
