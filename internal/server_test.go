package tfa

import (
	"fmt"
	"github.com/coreos/go-oidc"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"

	intlog "github.com/mesosphere/traefik-forward-auth/internal/log"
)

// TODO:

/**
 * Setup
 */

func init() {
	_ = intlog.NewDefaultLogger("debug", "panic")
}

/**
 * Tests
 */

type fakeStore struct {
	fakeGroups []string
}

func (f *fakeStore) fakeSession() *sessions.Session {
	return &sessions.Session{
		ID:      "1",
		Values:  map[interface{}]interface{}{"groups": f.fakeGroups},
		Options: nil,
		IsNew:   false,
	}
}
func (f *fakeStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return f.fakeSession(), nil
}

func (f *fakeStore) New(r *http.Request, name string) (*sessions.Session, error) {
	return f.fakeSession(), nil
}

func (f *fakeStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	return nil
}

func TestServerAuthHandlerInvalid(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	config.AuthHost = "dex.example.com"
	config.Lifetime = time.Minute * time.Duration(config.LifetimeString)
	// Should redirect vanilla request to login url
	req := newDefaultHttpRequest("/foo")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "vanilla request should be redirected")

	// Should catch invalid cookie
	req = newDefaultHttpRequest("/foo")
	c := MakeIDCookie(req, "test@example.com")
	parts := strings.Split(c.Value, "|")
	c.Value = fmt.Sprintf("bad|%s|%s", parts[1], parts[2])

	config.AuthHost = ""
	config.OIDCProvider = &oidc.Provider{}
	res, _ = doHttpRequest(req, c)
	assert.Equal(302, res.StatusCode, "invalid cookie should redirect")

	// Should validate email
	req = newDefaultHttpRequest("/foo")
	c = MakeIDCookie(req, "test@example.com")
	config.Domains = []string{"test.com"}

	res, _ = doHttpRequest(req, c)
	assert.Equal(401, res.StatusCode, "invalid email should not be authorised")
}

func TestServerAuthHandlerExpired(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	config.Lifetime = time.Second * time.Duration(-1)
	config.Domains = []string{"test.com"}
	config.AuthHost = "potato.example.com"

	// Should redirect expired cookie
	req := newDefaultHttpRequest("/foo")
	c := MakeIDCookie(req, "test@example.com")
	res, _ := doHttpRequest(req, c)
	assert.Equal(307, res.StatusCode, "request with expired cookie should be redirected")

	// Check redirection location
	fwd, _ := res.Location()
	assert.Equal("https", fwd.Scheme, "request with expired cookie should be redirected to authhost")
	assert.Equal("potato.example.com", fwd.Host, "request with expired cookie should be redirected to authhost")
	assert.Equal("/foo", fwd.Path, "requests with an expired cookie should be redirected back to auth host")
}

func TestServerAuthHandlerValid(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	config.Lifetime = time.Minute * time.Duration(config.LifetimeString)
	// Should allow valid request email
	req := newDefaultHttpRequest("/foo")
	c := MakeIDCookie(req, "test@example.com")

	config.Domains = []string{}

	res, _ := doHttpRequest(req, c)
	assert.Equal(200, res.StatusCode, "valid request should be allowed")

	// Should pass through user
	users := res.Header["X-Forwarded-User"]
	assert.Len(users, 1, "valid request should have X-Forwarded-User header")
	assert.Equal([]string{"test@example.com"}, users, "X-Forwarded-User header should match user")
}

// TODO: OIDC exchanges need to be mocked for AuthCallback testing
//func TestServerAuthCallback(t *testing.T) {
//	assert := assert.New(t)
//	config, _ = NewConfig([]string{})
//	config.AuthHost = "potato.example.com"
//
//	// Setup token server
//	tokenServerHandler := &TokenServerHandler{}
//	tokenServer := httptest.NewServer(tokenServerHandler)
//	defer tokenServer.Close()
//
//	// Setup user server
//	userServerHandler := &UserServerHandler{}
//	userServer := httptest.NewServer(userServerHandler)
//	defer userServer.Close()
//
//	// Should pass auth response request to callback
//	req := newDefaultHttpRequest("/_oauth")
//	res, _ := doHttpRequest(req, nil)
//	assert.Equal(401, res.StatusCode, "auth callback without cookie shouldn't be authorised")
//
//	// Should catch invalid csrf cookie
//	req = newDefaultHttpRequest("/_oauth?state=12345678901234567890123456789012:http://redirect")
//	c := MakeCSRFCookie(req, "nononononononononononononononono")
//	res, _ = doHttpRequest(req, c)
//	assert.Equal(401, res.StatusCode, "auth callback with invalid cookie shouldn't be authorised")
//
//	// Should redirect valid request
//	req = newDefaultHttpRequest("/_oauth?state=12345678901234567890123456789012:http://redirect")
//	c = MakeCSRFCookie(req, "12345678901234567890123456789012")
//	res, _ = doHttpRequest(req, c)
//	assert.Equal(307, res.StatusCode, "valid auth callback should be allowed")
//
//	fwd, _ := res.Location()
//	assert.Equal("http", fwd.Scheme, "valid request should be redirected to return url")
//	assert.Equal("redirect", fwd.Host, "valid request should be redirected to return url")
//	assert.Equal("", fwd.Path, "valid request should be redirected to return url")
//}

func TestServerDefaultAction(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	config.AuthHost = "potato.example.com"
	req := newDefaultHttpRequest("/random")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request should require auth with auth default handler")

	config.DefaultAction = "allow"
	config.AuthHost = ""
	req = newDefaultHttpRequest("/random")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request should be allowed with default handler")
}

func TestServerRouteHeaders(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	config.AuthHost = "potato.example.com"
	config.Rules = map[string]*Rule{
		"1": {
			Action: "allow",
			Rule:   "Headers(`X-Test`, `test123`)",
		},
		"2": {
			Action: "allow",
			Rule:   "HeadersRegexp(`X-Test`, `test(456|789)`)",
		},
	}

	// Should block any request
	req := newDefaultHttpRequest("/random")
	req.Header.Add("X-Random", "hello")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	config.AuthHost = ""
	// Should allow matching
	req = newDefaultHttpRequest("/api")
	req.Header.Add("X-Test", "test123")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	// Should allow matching
	req = newDefaultHttpRequest("/api")
	req.Header.Add("X-Test", "test789")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestServerRouteHost(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	config.Rules = map[string]*Rule{
		"1": {
			Action: "allow",
			Rule:   "Host(`api.example.com`)",
		},
		"2": {
			Action: "allow",
			Rule:   "HostRegexp(`sub{num:[0-9]}.example.com`)",
		},
	}

	config.AuthHost = "potato.example.com"

	// Should block any request
	req := newHttpRequest("GET", "https://example.com/", "/")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	config.AuthHost = ""
	// Should allow matching request
	req = newHttpRequest("GET", "https://api.example.com/", "/")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	// Should allow matching request
	req = newHttpRequest("GET", "https://sub8.example.com/", "/")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestServerRouteMethod(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	config.Rules = map[string]*Rule{
		"1": {
			Action: "allow",
			Rule:   "Method(`PUT`)",
		},
	}

	config.AuthHost = "potato.example.com"
	// Should block any request
	req := newHttpRequest("GET", "https://example.com/", "/")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	config.AuthHost = ""
	// Should allow matching request
	req = newHttpRequest("PUT", "https://example.com/", "/")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestServerRoutePath(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	config.Rules = map[string]*Rule{
		"1": {
			Action: "allow",
			Rule:   "Path(`/api`)",
		},
		"2": {
			Action: "allow",
			Rule:   "PathPrefix(`/private`)",
		},
	}

	config.AuthHost = "potato.example.com"
	// Should block any request
	req := newDefaultHttpRequest("/random")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	config.AuthHost = ""
	// Should allow /api request
	req = newDefaultHttpRequest("/api")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	// Should allow /private request
	req = newDefaultHttpRequest("/private")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	req = newDefaultHttpRequest("/private/path")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	// Should allow matching request
	req = newDefaultHttpRequest("/path")
	req.Header.Add("X-Forwarded-Prefix", "/private")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	// Should allow matching request
	req = newDefaultHttpRequest("/replaced/path")
	req.Header.Add("X-Replaced-Path", "/private/path")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestServerRouteQuery(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	config.Rules = map[string]*Rule{
		"1": {
			Action: "allow",
			Rule:   "Query(`q=test123`)",
		},
	}

	config.AuthHost = "potato.example.com"
	// Should block any request
	req := newHttpRequest("GET", "https://example.com/", "/?q=no")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	config.AuthHost = ""
	// Should allow matching request
	req = newHttpRequest("GET", "https://api.example.com/", "/?q=test123")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestAuthzDisabled(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})

	config.EnableRBAC = true
	config.AuthZPassThrough = []string{"/authz/passthru", "/authz/passthru/*"}
	s := NewServer(&fakeStore{}, fake.NewSimpleClientset())

	var r *http.Request
	r = httptest.NewRequest("get", "http://x//rbac", nil)
	assert.Equal(s.authzIsBypassed(r), false, "/rbac should not be skipped")
	r = httptest.NewRequest("get", "http://x/authz/passthru", nil)
	assert.Equal(s.authzIsBypassed(r), true)
	r = httptest.NewRequest("get", "http://x/authz/passthru/1234", nil)
	assert.Equal(s.authzIsBypassed(r), true)
}

/**
 * Utilities
 */

type TokenServerHandler struct{}

func (t *TokenServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `{"access_token":"123456789"}`)
}

type UserServerHandler struct{}

func (t *UserServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `{
    "id":"1",
    "email":"example@example.com",
    "verified_email":true,
    "hd":"example.com"
  }`)
}

func doHttpRequest(r *http.Request, c *http.Cookie) (*http.Response, string) {
	w := httptest.NewRecorder()

	// Set cookies on recorder
	if c != nil {
		http.SetCookie(w, c)
	}

	// Copy into request
	for _, c := range w.HeaderMap["Set-Cookie"] {
		r.Header.Add("Cookie", c)
	}

	s := NewServer(&fakeStore{}, nil)

	s.RootHandler(w, r)
	res := w.Result()
	body, _ := ioutil.ReadAll(res.Body)

	// if res.StatusCode > 300 && res.StatusCode < 400 {
	// 	fmt.Printf("%#v", res.Header)
	// }

	return res, string(body)
}

func newDefaultHttpRequest(uri string) *http.Request {
	return newHttpRequest("", "http://example.com/", uri)
}

func newHttpRequest(method, dest, uri string) *http.Request {
	r := httptest.NewRequest("", "http://should-use-x-forwarded.com", nil)
	p, _ := url.Parse(dest)
	r.Header.Add("X-Forwarded-Method", method)
	r.Header.Add("X-Forwarded-Host", p.Host)
	r.Header.Add("X-Forwarded-Uri", uri)
	r.Header.Add("X-Forwarded-Proto", "https")
	r.Header.Add("Accept", "*/*")
	return r
}

func qsDiff(t *testing.T, one, two url.Values) []string {
	errs := make([]string, 0)
	for k := range one {
		if two.Get(k) == "" {
			errs = append(errs, fmt.Sprintf("Key missing: %s", k))
		}
		if one.Get(k) != two.Get(k) {
			errs = append(errs, fmt.Sprintf("Value different for %s: expected: '%s' got: '%s'", k, one.Get(k), two.Get(k)))
		}
	}
	for k := range two {
		if one.Get(k) == "" {
			errs = append(errs, fmt.Sprintf("Extra key: %s", k))
		}
	}
	return errs
}
