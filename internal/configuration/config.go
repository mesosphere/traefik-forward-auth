package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	"github.com/thomseddon/go-flags"

	logger "github.com/turnly/oauth-middleware/internal/log"
	"github.com/turnly/oauth-middleware/internal/util"
)

var (
	log logrus.FieldLogger
)

// Config holds app configuration
type Config struct {
	LogLevel  string `long:"log-level" env:"LOG_LEVEL" default:"warn" choice:"trace" choice:"debug" choice:"info" choice:"warn" choice:"error" choice:"fatal" choice:"panic" description:"Log level"`
	LogFormat string `long:"log-format"  env:"LOG_FORMAT" default:"text" choice:"text" choice:"json" choice:"pretty" description:"Log format"`

	ProviderURI            string               `long:"provider-uri" env:"PROVIDER_URI" description:"OIDC Provider URI"`
	ClientID               string               `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret           string               `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	Scope                  string               `long:"scope" env:"SCOPE" description:"Define scope"`
	AuthHost               string               `long:"auth-host" env:"AUTH_HOST" description:"Single host to use when returning from 3rd party auth"`
	Config                 func(s string) error `long:"config" env:"CONFIG" description:"Path to config file" json:"-"`
	CookieDomains          []util.CookieDomain  `long:"cookie-domain" env:"COOKIE_DOMAIN" description:"Domain to set auth cookie on, can be set multiple times"`
	InsecureCookie         bool                 `long:"insecure-cookie" env:"INSECURE_COOKIE" description:"Use insecure cookies"`
	CookieName             string               `long:"cookie-name" env:"COOKIE_NAME" default:"_forward_auth" description:"ID Cookie Name"`
	EmailHeaderNames       CommaSeparatedList   `long:"email-header-names" env:"EMAIL_HEADER_NAMES" default:"X-Forwarded-User" description:"Response headers containing the authenticated user's username"`
	UserCookieName         string               `long:"user-cookie-name" env:"USER_COOKIE_NAME" default:"_forward_auth_name" description:"User Cookie Name"`
	CSRFCookieName         string               `long:"csrf-cookie-name" env:"CSRF_COOKIE_NAME" default:"_forward_auth_csrf" description:"CSRF Cookie Name"`
	ClaimsSessionName      string               `long:"claims-session-name" env:"CLAIMS_SESSION_NAME" default:"_forward_auth_claims" description:"Name of the claims session"`
	DefaultAction          string               `long:"default-action" env:"DEFAULT_ACTION" default:"auth" choice:"auth" choice:"allow" description:"Default action"`
	Domains                CommaSeparatedList   `long:"domain" env:"DOMAIN" description:"Only allow given email domains, can be set multiple times"`
	LifetimeString         int                  `long:"lifetime" env:"LIFETIME" default:"43200" description:"Lifetime in seconds"`
	Path                   string               `long:"url-path" env:"URL_PATH" default:"/_oauth" description:"Callback URL Path"`
	SecretString           string               `long:"secret" env:"SECRET" description:"Secret used for signing the cookie (required)" json:"-"`
	Whitelist              CommaSeparatedList   `long:"whitelist" env:"WHITELIST" description:"Only allow given email addresses, can be set multiple times"`
	EnableImpersonation    bool                 `long:"enable-impersonation" env:"ENABLE_IMPERSONATION" description:"Indicates that impersonation headers should be set on successful auth"`
	ForwardTokenHeaderName string               `long:"forward-token-header-name" env:"FORWARD_TOKEN_HEADER_NAME" description:"Header name to forward the raw ID token in (won't forward token if empty)"`
	ForwardTokenPrefix     string               `long:"forward-token-prefix" env:"FORWARD_TOKEN_PREFIX" default:"Bearer " description:"Prefix string to add before the forwarded ID token"`
	Rules                  map[string]*Rule     `long:"rules.<name>.<param>" description:"Rule definitions, param can be: \"action\" or \"rule\""`
	GroupClaimPrefix       string               `long:"group-claim-prefix" env:"GROUP_CLAIM_PREFIX" default:"oidc:" description:"prefix oidc group claims with this value"`
	EncryptionKeyString    string               `long:"encryption-key" env:"ENCRYPTION_KEY" description:"Encryption key used to encrypt the cookie (required)" json:"-"`
	GroupsAttributeName    string               `long:"groups-attribute-name" env:"GROUPS_ATTRIBUTE_NAME" default:"groups" description:"Map the correct attribute that contain the user groups"`

	// Filled during transformations
	OIDCContext         context.Context
	OIDCProvider        *oidc.Provider
	Lifetime            time.Duration
	ServiceAccountToken string
}

// NewConfig loads config from provided args or uses os.Args if nil
func NewConfig(args []string) (*Config, error) {
	if args == nil && len(os.Args) > 0 {
		args = os.Args[1:]
	}

	c := Config{
		Rules: map[string]*Rule{},
	}

	err := c.parseFlags(args)

	// Set the client context explicitly in order to use proxy configuration from environment(if any)
	// See https://github.com/coreos/go-oidc/blob/8d771559cf6e5111c9b9159810d0e4538e7cdc82/oidc.go#L43-L53
	c.OIDCContext = oidc.ClientContext(context.Background(), &http.Client{})

	log = logger.NewDefaultLogger(c.LogLevel, c.LogFormat)
	return &c, err
}

func (c *Config) parseFlags(args []string) error {
	p := flags.NewParser(c, flags.Default|flags.IniUnknownOptionHandler)
	p.UnknownOptionHandler = c.parseUnknownFlag

	i := flags.NewIniParser(p)
	c.Config = func(s string) error {
		// Try parsing at as an ini
		err := i.ParseFile(s)

		// If it fails with a syntax error, try converting legacy to ini
		if err != nil && strings.Contains(err.Error(), "malformed key=value") {
			converted, convertErr := convertLegacyToIni(s)
			if convertErr != nil {
				// If conversion fails, return the original error
				return err
			}

			fmt.Println("config format deprecated, please use ini format")
			return i.Parse(converted)
		}

		return err
	}

	_, err := p.ParseArgs(args)
	if err != nil {
		return handleFlagError(err)
	}

	return nil
}

func (c *Config) parseUnknownFlag(option string, arg flags.SplitArgument, args []string) ([]string, error) {
	// Parse rules in the format "rule.<name>.<param>"
	parts := strings.Split(option, ".")
	if len(parts) == 3 && parts[0] == "rule" {
		// Ensure there is a name
		name := parts[1]
		if len(name) == 0 {
			return args, errors.New("route name is required")
		}

		// Get value, or pop the next arg
		val, ok := arg.Value()
		if !ok && len(args) > 1 {
			val = args[0]
			args = args[1:]
		}

		// Check value
		if len(val) == 0 {
			return args, errors.New("route param value is required")
		}

		// Unquote if required
		if val[0] == '"' {
			var err error
			val, err = strconv.Unquote(val)
			if err != nil {
				return args, err
			}
		}

		// Get or create rule
		rule, ok := c.Rules[name]
		if !ok {
			rule = NewRule()
			c.Rules[name] = rule
		}

		// Add param value to rule
		switch parts[2] {
		case "action":
			rule.Action = val
		case "rule":
			rule.Rule = val
		default:
			return args, fmt.Errorf("invalid route param: %v", option)
		}
	} else {
		return args, fmt.Errorf("unknown flag: %v", option)
	}

	return args, nil
}

func handleFlagError(err error) error {
	flagsErr, ok := err.(*flags.Error)
	if ok && flagsErr.Type == flags.ErrHelp {
		// Library has just printed cli help
		os.Exit(0)
	}

	return err
}

var legacyFileFormat = regexp.MustCompile(`(?m)^([a-z-]+) (.*)$`)

func convertLegacyToIni(name string) (io.Reader, error) {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(legacyFileFormat.ReplaceAll(b, []byte("$1=$2"))), nil
}

// Validate validates the provided config
func (c *Config) Validate() {
	// Check for show stopper errors
	if len(c.SecretString) == 0 {
		log.Fatal("Oops, you forgot to set the \"secret\" option. This is required for signing cookies.")
	} else if len(c.SecretString) < 32 {
		log.Infoln("Mmm, Your secret is only", len(c.SecretString), "bytes long. Consider using a 32 byte secret for better security.")
	}

	if c.ProviderURI == "" || c.ClientID == "" || c.ClientSecret == "" {
		log.Fatal("Oops, you forgot to set the \"provider-uri\", \"client-id\", or \"client-secret\" options. These are required for authenticating with the OpenID Connect provider.")
	}

	// Check rules
	for _, rule := range c.Rules {
		rule.Validate()
	}

	// Transformations
	if len(c.Path) > 0 && c.Path[0] != '/' {
		c.Path = "/" + c.Path
	}

	c.Lifetime = time.Second * time.Duration(c.LifetimeString)
}

// LoadOIDCProviderConfiguration loads the configuration of OpenID Connect provider
func (c *Config) LoadOIDCProviderConfiguration() error {
	// Fetch OIDC Provider configuration
	provider, err := oidc.NewProvider(c.OIDCContext, c.ProviderURI)

	if err != nil {
		return fmt.Errorf("Oops, unable to connect to the OpenID Connect provider %s: %v (hint: make sure %s is accessible from the cluster)",
			c.ProviderURI, err, c.ProviderURI)
	}

	c.OIDCProvider = provider

	return nil
}

// CookieExpiry returns the cookie expiration time (Now() + configured Lifetime)
func (c Config) CookieExpiry() time.Time {
	return time.Now().Local().Add(c.Lifetime)
}

// CookieMaxAge returns number of seconds to cookie expiration (configured Lifetime converted to seconds)
func (c Config) CookieMaxAge() int {
	return int(c.Lifetime / time.Second)
}

func (c Config) String() string {
	jsonConf, _ := json.Marshal(c)
	return string(jsonConf)
}

// Rule specifies an action for the rule
type Rule struct {
	Action string
	Rule   string
}

// NewRule creates a new Rule instance
func NewRule() *Rule {
	return &Rule{
		Action: "auth",
	}
}

func (r *Rule) FormattedRule() string {
	// Traefik implements their own "Host" matcher and then offers "HostRegexp"
	// to invoke the mux "Host" matcher. This ensures the mux version is used
	return strings.ReplaceAll(r.Rule, "Host(", "HostRegexp(")
}

// Validate validates the rule
func (r *Rule) Validate() {
	if r.Action != "auth" && r.Action != "allow" {
		log.Fatal("Oops, you have an invalid rule action. Valid actions are \"auth\" and \"allow\".")
	}
}

// Legacy support for comma separated lists

// CommaSeparatedList flag value
type CommaSeparatedList []string

// UnmarshalFlag unmarshals a comma-separated list from the flag value
func (c *CommaSeparatedList) UnmarshalFlag(value string) error {
	*c = append(*c, strings.Split(value, ",")...)
	return nil
}

// MarshalFlag marshals the comma-separated list to the flag value
func (c *CommaSeparatedList) MarshalFlag() (string, error) {
	return strings.Join(*c, ","), nil
}
