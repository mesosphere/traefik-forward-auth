package configuration

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/**
 * Tests
 */

func TestConfigDefaults(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{})

	assert.Nil(err)

	assert.Equal("warn", c.LogLevel)
	assert.Equal("text", c.LogFormat)

	assert.Equal("", c.AuthHost)
	assert.Len(c.CookieDomains, 0)
	assert.False(c.InsecureCookie)
	assert.Equal("_forward_auth", c.CookieName)
	assert.Equal("_forward_auth_csrf", c.CSRFCookieName)
	assert.Equal("auth", c.DefaultAction)
	assert.Len(c.Domains, 0)
	assert.Equal(43200, c.LifetimeString)
	assert.Equal("/_oauth", c.Path)
	assert.Len(c.Whitelist, 0)
}

func TestConfigParseArgs(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--cookie-name=cookiename",
		"--cookie-domain=example.com",
		"--cookie-domain=example2.com",
		"--csrf-cookie-name", "\"csrfcookiename\"",
		"--rule.1.action=allow",
		"--rule.1.rule=PathPrefix(`/one`)",
		"--rule.two.action=auth",
		"--rule.two.rule=\"Host(`two.com`) && Path(`/two`)\"",
	})
	require.Nil(t, err)

	// Check normal flags
	assert.Equal("cookiename", c.CookieName)
	assert.Equal("csrfcookiename", c.CSRFCookieName)

	// Check rules
	assert.Equal(map[string]*Rule{
		"1": {
			Action: "allow",
			Rule:   "PathPrefix(`/one`)",
		},
		"two": {
			Action: "auth",
			Rule:   "Host(`two.com`) && Path(`/two`)",
		},
	}, c.Rules)

	// Check cookie domain
	if assert.Len(c.CookieDomains, 2, "there must be 2 cookie domains") {
		assert.Equal("example.com", c.CookieDomains[0].Domain, "first cookie domain should be read from environment")
		assert.Equal("example2.com", c.CookieDomains[1].Domain, "second cookie domain should be read from environment")
	}
}

func TestConfigParseUnknownFlags(t *testing.T) {
	_, err := NewConfig([]string{
		"--unknown=_oauthpath2",
	})
	if assert.Error(t, err) {
		assert.Equal(t, "unknown flag: unknown", err.Error())
	}
}

func TestConfigParseRuleError(t *testing.T) {
	assert := assert.New(t)

	// Rule without name
	_, err := NewConfig([]string{
		"--rule..action=auth",
	})
	if assert.Error(err) {
		assert.Equal("route name is required", err.Error())
	}

	// Rule without value
	c, err := NewConfig([]string{
		"--rule.one.action=",
	})
	if assert.Error(err) {
		assert.Equal("route param value is required", err.Error())
	}
	// Check rules
	assert.Equal(map[string]*Rule{}, c.Rules)
}

func TestConfigParseIni(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--config=../../test/config0",
		"--config=../../test/config1",
		"--csrf-cookie-name=csrfcookiename",
	})
	require.Nil(t, err)

	assert.Equal("inicookiename", c.CookieName, "should be read from ini file")
	assert.Equal("csrfcookiename", c.CSRFCookieName, "should be read from ini file")
	assert.Equal("/two", c.Path, "variable in second ini file should override first ini file")
	assert.Equal(map[string]*Rule{
		"1": {
			Action: "allow",
			Rule:   "PathPrefix(`/one`)",
		},
		"two": {
			Action: "auth",
			Rule:   "Host(`two.com`) && Path(`/two`)",
		},
	}, c.Rules)
	if assert.Len(c.CookieDomains, 2, "there must be 2 cookie domains") {
		assert.Equal("example.com", c.CookieDomains[0].Domain, "first cookie domain should be read from environment")
		assert.Equal("example2.com", c.CookieDomains[1].Domain, "second cookie domain should be read from environment")
	}
}

func TestConfigParseEnvironment(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("COOKIE_NAME", "env_cookie_name")
	c, err := NewConfig([]string{})
	assert.Nil(err)

	assert.Equal("env_cookie_name", c.CookieName, "variable should be read from environment")

	os.Unsetenv("COOKIE_NAME")
}

func TestConfigParseCookieDomainFromEnvironment(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("COOKIE_DOMAIN", "example.com,example2.com")
	c, err := NewConfig([]string{})
	assert.Nil(err)

	if assert.Len(c.CookieDomains, 2, "there must be 2 cookie domains") {
		assert.Equal("example.com", c.CookieDomains[0].Domain, "first cookie domain should be read from environment")
		assert.Equal("example2.com", c.CookieDomains[1].Domain, "second cookie domain should be read from environment")
	}

	os.Unsetenv("COOKIE_DOMAIN")
}

func TestConfigParseScopeFromEnvironment(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("SCOPE", "openid email")
	c, err := NewConfig([]string{})
	assert.Nil(err)

	assert.Equal([]string{"openid", "email"}, c.Scope, "scope array should be populated")

	os.Unsetenv("SCOPE")
}

func TestConfigTransformation(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--url-path=_oauthpath",
		"--secret=verysecret",
		"--lifetime=200",
		"--provider-uri=dex.example.com",
		"--client-id=xyz",
		"--client-secret=very$ecret!",
	})
	require.Nil(t, err)
	c.Validate()

	assert.Equal("/_oauthpath", c.Path, "path should add slash to front")

	assert.Equal(200, c.LifetimeString)
	assert.Equal(time.Second*time.Duration(200), c.Lifetime, "lifetime should be read and converted to duration")
}

func TestConfigCommaSeparatedList(t *testing.T) {
	assert := assert.New(t)
	list := CommaSeparatedList{}

	err := list.UnmarshalFlag("one,two")
	assert.Nil(err)
	assert.Equal(CommaSeparatedList{"one", "two"}, list, "should parse comma sepearated list")

	marshal, err := list.MarshalFlag()
	assert.Nil(err)
	assert.Equal("one,two", marshal, "should marshal back to comma sepearated list")
}
