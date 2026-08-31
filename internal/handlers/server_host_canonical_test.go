package handlers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mesosphere/traefik-forward-auth/internal/configuration"
)

// TestServerHostCanonicalAuthRuleDefaultAllow is the unauthenticated bypass:
// default-action=allow with a Host(...) auth rule. Traefik routes both the
// canonical Host and the single-trailing-dot spelling to the same backend;
// both must select the auth rule, not fall through to allow.
func TestServerHostCanonicalAuthRuleDefaultAllow(t *testing.T) {
	assert := assert.New(t)
	config := newTestConfig(testAuthKey1, testEncKey1)
	config.DefaultAction = "allow"
	config.AuthHost = ""
	config.Rules = map[string]*configuration.Rule{
		"admin": {
			Action: "auth",
			Rule:   "Host(`admin.rig.test`)",
		},
	}

	for _, host := range []string{"admin.rig.test", "admin.rig.test.", "Admin.Rig.Test."} {
		req := newForwardedRequest(host)
		res, _ := doHttpRequest(req, nil, config)
		assert.Equal(401, res.StatusCode, "host %q must require auth", host)
	}

	req := newForwardedRequest("other.rig.test")
	res, _ := doHttpRequest(req, nil, config)
	assert.Equal(200, res.StatusCode, "unrelated host should use default allow")
}

// TestServerHostCanonicalDottedRule covers the inverse: a rule written with a
// trailing dot must still match the canonical Host, so writing the dotted form
// is not a workaround.
func TestServerHostCanonicalDottedRule(t *testing.T) {
	assert := assert.New(t)
	config := newTestConfig(testAuthKey1, testEncKey1)
	config.DefaultAction = "allow"
	config.AuthHost = ""
	config.Rules = map[string]*configuration.Rule{
		"admin": {
			Action: "auth",
			Rule:   "Host(`admin.rig.test.`)",
		},
	}

	for _, host := range []string{"admin.rig.test", "admin.rig.test."} {
		req := newForwardedRequest(host)
		res, _ := doHttpRequest(req, nil, config)
		assert.Equal(401, res.StatusCode, "host %q must match dotted Host rule", host)
	}
}

func TestServerHostCanonicalAllowRuleDefaultAuth(t *testing.T) {
	assert := assert.New(t)
	config := newTestConfig(testAuthKey1, testEncKey1)
	config.DefaultAction = "auth"
	config.AuthHost = ""
	config.Rules = map[string]*configuration.Rule{
		"public": {
			Action: "allow",
			Rule:   "Host(`public.rig.test`)",
		},
	}

	for _, host := range []string{"public.rig.test", "public.rig.test."} {
		req := newForwardedRequest(host)
		res, _ := doHttpRequest(req, nil, config)
		assert.Equal(200, res.StatusCode, "host %q must match allow rule", host)
	}

	req := newForwardedRequest("other.rig.test")
	res, _ := doHttpRequest(req, nil, config)
	assert.Equal(401, res.StatusCode, "unrelated host should use default auth")
}

func TestServerHostRegexpLeftAlone(t *testing.T) {
	assert := assert.New(t)
	config := newTestConfig(testAuthKey1, testEncKey1)
	config.DefaultAction = "allow"
	config.AuthHost = ""
	config.Rules = map[string]*configuration.Rule{
		"admin": {
			Action: "auth",
			Rule:   "HostRegexp(`admin.rig.test.`)",
		},
	}

	// HostRegexp arguments are not rewritten. After request-host
	// canonicalization the mux never sees a trailing dot, so a dotted
	// HostRegexp matches neither spelling.
	for _, host := range []string{"admin.rig.test", "admin.rig.test."} {
		req := newForwardedRequest(host)
		res, _ := doHttpRequest(req, nil, config)
		assert.Equal(200, res.StatusCode, "HostRegexp must not be auto-canonicalized; host %q", host)
	}
}

func TestServerAuthHostTrailingDot(t *testing.T) {
	assert := assert.New(t)
	config := newTestConfig(testAuthKey1, testEncKey1)
	config.DefaultAction = "allow"
	config.AuthHost = "auth.example.com"

	req := newForwardedRequest("auth.example.com.")
	res, _ := doHttpRequest(req, nil, config)
	assert.Equal(200, res.StatusCode, "dotted auth host must be treated as the auth host")
}

func TestCanonicalizeForwardedHost(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("", canonicalizeForwardedHost(""))
	assert.Equal("admin.rig.test", canonicalizeForwardedHost("admin.rig.test"))
	assert.Equal("admin.rig.test", canonicalizeForwardedHost("admin.rig.test."))
	assert.Equal("admin.rig.test.", canonicalizeForwardedHost("admin.rig.test.."))
	assert.Equal("admin.rig.test", canonicalizeForwardedHost("Admin.Rig.Test."))
	assert.Equal("admin.rig.test:8443", canonicalizeForwardedHost("admin.rig.test:8443"))
	assert.Equal("admin.rig.test:8443", canonicalizeForwardedHost("admin.rig.test.:8443"))
	assert.Equal("[::1]:8443", canonicalizeForwardedHost("[::1]:8443"))
	assert.Equal("[2001:db8::1]:443", canonicalizeForwardedHost("[2001:db8::1]:443"))
}

func newForwardedRequest(host string) *http.Request {
	req := newHTTPRequest("GET", "https://example.com/", "/")
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("Accept", "application/json")
	return req
}
