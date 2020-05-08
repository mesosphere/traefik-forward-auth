package tfa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	"github.com/thomseddon/go-flags"

	internallog "github.com/mesosphere/traefik-forward-auth/internal/log"
)

var (
	// TODO(jr): Get rid of the global config object
	config *Config
	log    logrus.FieldLogger
)

type Config struct {
	LogLevel  string `long:"log-level" env:"LOG_LEVEL" default:"warn" choice:"trace" choice:"debug" choice:"info" choice:"warn" choice:"error" choice:"fatal" choice:"panic" description:"Log level"`
	LogFormat string `long:"log-format"  env:"LOG_FORMAT" default:"text" choice:"text" choice:"json" choice:"pretty" description:"Log format"`

	ProviderUri             string               `long:"provider-uri" env:"PROVIDER_URI" description:"OIDC Provider URI"`
	ClientId                string               `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret            string               `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	Scope                   string               `long:"scope" env:"SCOPE" description:"Define scope"`
	AuthHost                string               `long:"auth-host" env:"AUTH_HOST" description:"Single host to use when returning from 3rd party auth"`
	Config                  func(s string) error `long:"config" env:"CONFIG" description:"Path to config file" json:"-"`
	CookieDomains           []CookieDomain       `long:"cookie-domain" env:"COOKIE_DOMAIN" description:"Domain to set auth cookie on, can be set multiple times"`
	InsecureCookie          bool                 `long:"insecure-cookie" env:"INSECURE_COOKIE" description:"Use insecure cookies"`
	CookieName              string               `long:"cookie-name" env:"COOKIE_NAME" default:"_forward_auth" description:"ID Cookie Name"`
	UserCookieName          string               `long:"user-cookie-name" env:"USER_COOKIE_NAME" default:"_forward_auth_name" description:"User Cookie Name"`
	CSRFCookieName          string               `long:"csrf-cookie-name" env:"CSRF_COOKIE_NAME" default:"_forward_auth_csrf" description:"CSRF Cookie Name"`
	GroupsSessionName       string               `long:"groups-session-name" env:"GROUPS_SESSION_NAME" default:"_forward_auth_claims" description:"Groups Session Name"`
	DefaultAction           string               `long:"default-action" env:"DEFAULT_ACTION" default:"auth" choice:"auth" choice:"allow" description:"Default action"`
	Domains                 CommaSeparatedList   `long:"domain" env:"DOMAIN" description:"Only allow given email domains, can be set multiple times"`
	LifetimeString          int                  `long:"lifetime" env:"LIFETIME" default:"43200" description:"Lifetime in seconds"`
	Path                    string               `long:"url-path" env:"URL_PATH" default:"/_oauth" description:"Callback URL Path"`
	SecretString            string               `long:"secret" env:"SECRET" description:"Secret used for signing (required)" json:"-"`
	Whitelist               CommaSeparatedList   `long:"whitelist" env:"WHITELIST" description:"Only allow given email addresses, can be set multiple times"`
	EnableImpersonation     bool                 `long:"enable-impersonation" env:"ENABLE_IMPERSONATION" description:"Indicates that impersonation headers should be set on successful auth"`
	ServiceAccountTokenPath string               `long:"service-account-token-path" env:"SERVICE_ACCOUNT_TOKEN_PATH" default:"/var/run/secrets/kubernetes.io/serviceaccount/token" description:"When impersonation is enabled, this token is passed via the Authorization header to the ingress. The user associated with the token must have impersonation privileges."`
	Rules                   map[string]*Rule     `long:"rules.<name>.<param>" description:"Rule definitions, param can be: \"action\" or \"rule\""`
	GroupClaimPrefix        string               `long:"group-claim-prefix" env:"GROUP_CLAIM_PREFIX" default:"oidc:" description:"prefix oidc group claims with this value"`
	SessionKey              string               `long:"session-key" env:"SESSION_KEY" description:"A session key used to encrypt browser sessions"`
	GroupsAttributeName     string               `long:"groups-attribute-name" env:"GROUPS_ATTRIBUTE_NAME" default:"groups" description:"Map the correct attribute that contain the user groups"`

	// RBAC
	EnableRBAC       bool               `long:"enable-rbac" env:"ENABLE_RBAC" description:"Indicates that RBAC support should be enabled"`
	AuthZPassThrough CommaSeparatedList `long:"authz-pass-through" env:"AUTHZ_PASS_THROUGH" description:"One or more routes which bypass authorization checks"`

	// Filled during transformations
	OIDCContext         context.Context
	OIDCProvider        *oidc.Provider
	Secret              []byte `json:"-"`
	Lifetime            time.Duration
	ServiceAccountToken string
}

func NewGlobalConfig() *Config {
	var err error
	config, err = NewConfig(os.Args[1:])
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	return config
}

func NewConfig(args []string) (*Config, error) {
	c := Config{
		Rules: map[string]*Rule{},
	}

	err := c.parseFlags(args)

	log = internallog.NewDefaultLogger(c.LogLevel, c.LogFormat)
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

func (c *Config) Validate() {
	// Check for show stopper errors
	if len(c.SecretString) == 0 {
		log.Fatal("\"secret\" option must be set.")
	} else if len(c.SecretString) < 32 {
		log.Infoln("for better security, \"secret\" should ideally be 32 bytes or longer")
	}

	if c.ProviderUri == "" || c.ClientId == "" || c.ClientSecret == "" {
		log.Fatal("provider-uri, client-id, client-secret must be set")
	}

	// Check rules
	for _, rule := range c.Rules {
		rule.Validate()
	}

	// Transformations
	if len(c.Path) > 0 && c.Path[0] != '/' {
		c.Path = "/" + c.Path
	}
	c.Secret = []byte(c.SecretString)
	c.Lifetime = time.Second * time.Duration(c.LifetimeString)

	// get service account token
	if c.EnableImpersonation {
		t, err := ioutil.ReadFile(c.ServiceAccountTokenPath)
		if err != nil {
			log.Fatalf("impersonation is enabled, but failed to read %s : %v", c.ServiceAccountTokenPath, err)
		}
		c.ServiceAccountToken = strings.TrimSuffix(string(t), "\n")
	}

	// RBAC
	if c.EnableRBAC && len(c.SessionKey) != 16 && len(c.SessionKey) != 24 && len(c.SessionKey) != 32 {
		// Gorilla sessions require encryption keys of specific length
		// https://www.gorillatoolkit.org/pkg/sessions#NewCookieStore
		log.Fatal("\"session-key\" must be 16, 24 or 32 bytes long to select AES-128, AES-192, or AES-256 modes")
	}
}

func (c *Config) SetOidcProvider() {
	// Fetch OIDC Provider configuration
	c.OIDCContext = context.Background()
	provider, err := oidc.NewProvider(c.OIDCContext, c.ProviderUri)
	if err != nil {
		log.Fatal("failed to get provider configuration for %s: %v (hint: make sure %s is accessible from the cluster)", c.ProviderUri, err, c.ProviderUri)
	}
	c.OIDCProvider = provider
}

func (c Config) String() string {
	jsonConf, _ := json.Marshal(c)
	return string(jsonConf)
}

type Rule struct {
	Action string
	Rule   string
}

func NewRule() *Rule {
	return &Rule{
		Action: "auth",
	}
}

func (r *Rule) formattedRule() string {
	// Traefik implements their own "Host" matcher and then offers "HostRegexp"
	// to invoke the mux "Host" matcher. This ensures the mux version is used
	return strings.ReplaceAll(r.Rule, "Host(", "HostRegexp(")
}

func (r *Rule) Validate() {
	if r.Action != "auth" && r.Action != "allow" {
		log.Fatal("invalid rule action, must be \"auth\" or \"allow\"")
	}
}

// Legacy support for comma separated lists

type CommaSeparatedList []string

func (c *CommaSeparatedList) UnmarshalFlag(value string) error {
	*c = append(*c, strings.Split(value, ",")...)
	return nil
}

func (c *CommaSeparatedList) MarshalFlag() (string, error) {
	return strings.Join(*c, ","), nil
}
