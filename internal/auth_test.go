package tfa

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	testAuthKey1 = "4Zhbg4n22r4I8Kdg1gHMzRWQpT7TOArD"
	testAuthKey2 = "HhaAG845dg9b16xKk8yiX+XoBhEAeHnQ"
	testEncKey1  = "8jAnK6NGuzEuH3y13V+5Bm2jgp5bv8ku"
	testEncKey2  = "FmvAqxzYy9ru0WaSU6SkLHP1ScoSVF/t"
)

func newTestConfig(authKey, encKey string) *Config {
	c, _ := NewConfig([]string{})
	c.SecretString = authKey
	c.EncryptionKeyString = encKey

	return c
}

/**
 * Tests
 */

func TestAuthValidateCookie(t *testing.T) {
	assert := assert.New(t)
	config = newTestConfig(testAuthKey1, testEncKey1)
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	c := &http.Cookie{}

	// Should not accept an empty value
	c.Value = ""
	_, err := validateSessionCookie(r, c)
	if assert.Error(err) {
		assert.Equal("securecookie: the value is not valid", err.Error())
	}

	// Should catch invalid mac
	c.Value = "MQ=="
	_, err = validateSessionCookie(r, c)
	if assert.Error(err) {
		assert.Equal("securecookie: the value is not valid", err.Error())
	}

	// Should catch expired
	config.Lifetime = time.Second * time.Duration(-1)
	c = makeSessionCookie(r, sessionCookie{EMail: "test@test.com"})
	_, err = validateSessionCookie(r, c)
	if assert.Error(err) {
		assert.Equal("securecookie: expired timestamp", err.Error())
	}

	// Should accept valid cookie
	config.Lifetime = time.Second * time.Duration(10)
	c = makeSessionCookie(r, sessionCookie{EMail: "test@test.com"})
	sess, err := validateSessionCookie(r, c)
	assert.Nil(err, "valid request should not return an error")
	assert.Equal("test@test.com", sess.EMail, "valid request should return user email")
}

func TestAuthValidateEmail(t *testing.T) {
	assert := assert.New(t)
	config = newTestConfig(testAuthKey1, testEncKey1)

	// Should allow any
	v := validateEmail("test@test.com")
	assert.True(v, "should allow any domain if email domain is not defined")
	v = validateEmail("one@two.com")
	assert.True(v, "should allow any domain if email domain is not defined")

	// Should block non matching domain
	config.Domains = []string{"test.com"}
	v = validateEmail("one@two.com")
	assert.False(v, "should not allow user from another domain")

	// Should allow matching domain
	config.Domains = []string{"test.com"}
	v = validateEmail("test@test.com")
	assert.True(v, "should allow user from allowed domain")

	// Should block non whitelisted email address
	config.Domains = []string{}
	config.Whitelist = []string{"test@test.com"}
	v = validateEmail("one@two.com")
	assert.False(v, "should not allow user not in whitelist")

	// Should allow matching whitelisted email address
	config.Domains = []string{}
	config.Whitelist = []string{"test@test.com"}
	v = validateEmail("test@test.com")
	assert.True(v, "should allow user in whitelist")
}

// TODO
// func TestAuthExchangeCode(t *testing.T) {
// }

// TODO
// func TestAuthGetUser(t *testing.T) {
// }

func getConfigWithLifetime() *Config {
	config = newTestConfig(testAuthKey1, testEncKey1)
	// Lifetime is set during validation, so we short circuit it here
	config.Lifetime = time.Second * time.Duration(config.LifetimeString)
	return config
}

func TestAuthMakeCookie(t *testing.T) {
	assert := assert.New(t)
	config = getConfigWithLifetime()

	r, _ := http.NewRequest("GET", "http://app.example.com", nil)
	r.Header.Add("X-Forwarded-Host", "app.example.com")

	c := makeSessionCookie(r, sessionCookie{EMail: "test@example.com"})
	assert.Equal("_forward_auth", c.Name)
	assert.Greater(len(c.Value), 18, "encoded securecookie should be longer")
	_, err := validateSessionCookie(r, c)
	assert.Nil(err, "should generate valid cookie")
	assert.Equal("/", c.Path)
	assert.Equal("app.example.com", c.Domain)
	assert.True(c.Secure)

	expires := time.Now().Local().Add(config.Lifetime)
	assert.WithinDuration(expires, c.Expires, 10*time.Second)

	config.CookieName = "testname"
	config.InsecureCookie = true
	c = makeSessionCookie(r, sessionCookie{EMail: "test@example.com"})
	assert.Equal("testname", c.Name)
	assert.False(c.Secure)
}

func TestAuthMakeCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	config = getConfigWithLifetime()
	r, _ := http.NewRequest("GET", "http://app.example.com", nil)
	r.Header.Add("X-Forwarded-Host", "app.example.com")

	// No cookie domain or auth url
	c := makeCSRFCookie(r, "12345678901234567890123456789012")
	assert.Equal("app.example.com", c.Domain)

	// With cookie domain but no auth url
	config = &Config{
		CookieDomains: []CookieDomain{*newCookieDomain("example.com")},
	}
	c = makeCSRFCookie(r, "12345678901234567890123456789012")
	assert.Equal("app.example.com", c.Domain)

	// With cookie domain and auth url
	config = &Config{
		AuthHost:      "auth.example.com",
		CookieDomains: []CookieDomain{*newCookieDomain("example.com")},
	}
	c = makeCSRFCookie(r, "12345678901234567890123456789012")
	assert.Equal("example.com", c.Domain)
}

func TestAuthClearCSRFCookie(t *testing.T) {
	config = getConfigWithLifetime()
	r, _ := http.NewRequest("GET", "http://example.com", nil)

	c := clearCSRFCookie(r)
	if c.Value != "" {
		t.Error("ClearCSRFCookie should create cookie with empty value")
	}
}

func TestAuthValidateCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	config = getConfigWithLifetime()
	c := &http.Cookie{}

	newCsrfRequest := func(state string) *http.Request {
		u := fmt.Sprintf("http://example.com?state=%s", state)
		r, _ := http.NewRequest("GET", u, nil)
		return r
	}

	// Should require 32 char string
	r := newCsrfRequest("")
	c.Value = ""
	valid, _, err := validateCSRFCookie(r, c)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF cookie value", err.Error())
	}
	c.Value = "123456789012345678901234567890123"
	valid, _, err = validateCSRFCookie(r, c)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF cookie value", err.Error())
	}

	// Should require valid state
	r = newCsrfRequest("12345678901234567890123456789012:")
	c.Value = "12345678901234567890123456789012"
	valid, _, err = validateCSRFCookie(r, c)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF state value", err.Error())
	}

	// Should allow valid state
	r = newCsrfRequest("12345678901234567890123456789012:99")
	c.Value = "12345678901234567890123456789012"
	valid, state, err := validateCSRFCookie(r, c)
	assert.True(valid, "valid request should return valid")
	assert.Nil(err, "valid request should not return an error")
	assert.Equal("99", state, "valid request should return correct state")
}

func TestAuthNonce(t *testing.T) {
	assert := assert.New(t)
	nonce1, err := generateNonce()
	assert.Nil(err, "error generating nonce")
	assert.Len(nonce1, 32, "length should be 32 chars")

	nonce2, err := generateNonce()
	assert.Nil(err, "error generating nonce")
	assert.Len(nonce2, 32, "length should be 32 chars")

	assert.NotEqual(nonce1, nonce2, "nonce should not be equal")
}

func TestAuthCookieDomainMatch(t *testing.T) {
	assert := assert.New(t)
	cd := newCookieDomain("example.com")

	// Exact should match
	assert.True(cd.Match("example.com"), "exact domain should match")

	// Subdomain should match
	assert.True(cd.Match("test.example.com"), "subdomain should match")

	// Derived domain should not match
	assert.False(cd.Match("testexample.com"), "derived domain should not match")

	// Other domain should not match
	assert.False(cd.Match("test.com"), "other domain should not match")
}

func TestAuthCookieDomains(t *testing.T) {
	assert := assert.New(t)
	cds := CookieDomains{}

	err := cds.UnmarshalFlag("one.com,two.org")
	assert.Nil(err)
	expected := CookieDomains{
		CookieDomain{
			Domain:       "one.com",
			DomainLen:    7,
			SubDomain:    ".one.com",
			SubDomainLen: 8,
		},
		CookieDomain{
			Domain:       "two.org",
			DomainLen:    7,
			SubDomain:    ".two.org",
			SubDomainLen: 8,
		},
	}
	assert.Equal(expected, cds)

	marshal, err := cds.MarshalFlag()
	assert.Nil(err)
	assert.Equal("one.com,two.org", marshal)
}
