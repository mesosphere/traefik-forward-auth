package authentication

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"

	"github.com/turnly/oauth-middleware/internal/configuration"
)

type Authenticator struct {
	config       *configuration.Config
	secureCookie *securecookie.SecureCookie
}

func NewAuthenticator(config *configuration.Config) *Authenticator {
	cookieMaxAge := config.CookieMaxAge()
	hashKey := []byte(config.SecretString)
	blockKey := []byte(config.EncryptionKeyString)

	return &Authenticator{
		config:       config,
		secureCookie: securecookie.New(hashKey, blockKey).MaxAge(cookieMaxAge),
	}
}

type ID struct {
	Email string
	Token string
}

// Request Validation

// ValidateCookie validates the ID cookie in the request
// IDCookie = hash(secret, cookie domain, email, expires)|expires|email|group
func (a *Authenticator) ValidateCookie(r *http.Request, c *http.Cookie) (*ID, error) {
	var data ID

	if err := a.secureCookie.Decode(a.config.CookieName, c.Value, &data); err != nil {
		return nil, err
	}

	return &data, nil
}

// ValidateEmail validates that the provided email ends with one of the configured Domains or is part of the configured Whitelist.
// Also returns true if there is no Whitelist and no Domains configured.
func (a *Authenticator) ValidateEmail(email string) bool {
	if len(a.config.Whitelist) > 0 || len(a.config.Domains) > 0 {
		for _, whitelist := range a.config.Whitelist {
			if email == whitelist {
				return true
			}
		}

		parts := strings.Split(email, "@")
		for _, domain := range a.config.Domains {
			if len(parts) >= 2 && domain == parts[1] {
				return true
			}
		}
		return false
	}
	return true
}

// ComposeRedirectURI generates oauth redirect uri to return to from the OAuth2 provider
func (a *Authenticator) ComposeRedirectURI(r *http.Request) string {
	if use, _ := a.useAuthDomain(r); use {
		scheme := r.Header.Get("X-Forwarded-Proto")
		return fmt.Sprintf("%s://%s%s", scheme, a.config.AuthHost, a.config.Path)

	}

	return fmt.Sprintf("%s%s", getRequestSchemeHost(r), a.config.Path)
}

// useAuthDomain decides whether the host of the forwarded request
// matches the configured AuthHost and whether we can configure cookies for the AuthHost
// If it does, the function returns true and the top-level domain from the config we can use
func (a *Authenticator) useAuthDomain(r *http.Request) (bool, string) {
	if a.config.AuthHost == "" {
		return false, ""
	}

	// Does the request match a given cookie domain?
	reqMatch, reqHost := a.matchCookieDomains(r.Header.Get("X-Forwarded-Host"))

	// Do any of the auth hosts match a cookie domain?
	authMatch, authHost := a.matchCookieDomains(a.config.AuthHost)

	// We need both to match the same domain
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// Cookie methods

// MakeIDCookie creates an auth cookie
func (a *Authenticator) MakeIDCookie(r *http.Request, email string, token string) (*http.Cookie, error) {
	expires := a.config.CookieExpiry()
	data := &ID{
		Email: email,
		Token: token,
	}

	encoded, err := a.secureCookie.Encode(a.config.CookieName, data)
	if err != nil {
		return nil, err
	}

	cookie := &http.Cookie{
		Name:     a.config.CookieName,
		Value:    encoded,
		Path:     "/",
		Domain:   a.GetCookieDomain(r),
		HttpOnly: true,
		Secure:   !a.config.InsecureCookie,
		Expires:  expires,
	}

	return cookie, nil
}

func (a *Authenticator) ClearIDCookie(r *http.Request) *http.Cookie {
	expires := a.config.CookieExpiry()

	return &http.Cookie{
		Name:     a.config.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   a.GetCookieDomain(r),
		HttpOnly: true,
		Secure:   !a.config.InsecureCookie,
		Expires:  expires,
	}
}

// MakeNameCookie creates a name cookie
func (a *Authenticator) MakeNameCookie(r *http.Request, name string) *http.Cookie {
	expires := a.config.CookieExpiry()

	return &http.Cookie{
		Name:     a.config.UserCookieName,
		Value:    name,
		Path:     "/",
		Domain:   a.GetCookieDomain(r),
		HttpOnly: false,
		Secure:   false,
		Expires:  expires,
	}
}

func (a *Authenticator) ClearNameCookie(r *http.Request) *http.Cookie {
	expires := a.config.CookieExpiry()

	return &http.Cookie{
		Name:     a.config.UserCookieName,
		Value:    "",
		Path:     "/",
		Domain:   a.GetCookieDomain(r),
		HttpOnly: false,
		Secure:   false,
		Expires:  expires,
	}
}

// MakeCSRFCookie creates a CSRF cookie (used during login only)
func (a *Authenticator) MakeCSRFCookie(r *http.Request, nonce string) *http.Cookie {
	return &http.Cookie{
		Name:     a.config.CSRFCookieName,
		Value:    nonce,
		Path:     "/",
		Domain:   a.csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !a.config.InsecureCookie,
		Expires:  a.config.CookieExpiry(),
	}
}

// ClearCSRFCookie clears the csrf cookie
func (a *Authenticator) ClearCSRFCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     a.config.CSRFCookieName,
		Value:    "",
		Path:     "/",
		Domain:   a.csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !a.config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// ValidateCSRFCookie validates the csrf cookie against state
func ValidateCSRFCookie(r *http.Request, c *http.Cookie) (bool, string, error) {
	state := r.URL.Query().Get("state")

	if len(c.Value) != 32 {
		return false, "", errors.New("Invalid CSRF cookie value")
	}

	if len(state) < 34 {
		return false, "", errors.New("Invalid CSRF state value")
	}

	// Check nonce match
	if c.Value != state[:32] {
		return false, "", errors.New("CSRF cookie does not match state")
	}

	// Valid, return redirect
	return true, state[33:], nil
}

// GenerateNonce generates a random nonce string
func GenerateNonce() (string, error) {
	// Make nonce
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", nonce), nil
}

// Cookie domain
func (a *Authenticator) GetCookieDomain(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")

	// Check if any of the given cookie domains matches
	_, domain := a.matchCookieDomains(host)
	return domain
}

// Cookie domain
func (a *Authenticator) csrfCookieDomain(r *http.Request) string {
	var host string
	if use, domain := a.useAuthDomain(r); use {
		host = domain
	} else {
		host = r.Header.Get("X-Forwarded-Host")
	}

	// Remove port
	p := strings.Split(host, ":")
	return p[0]
}

// matchCookieDomains checks if the provided domain maches any domain configured in the CookieDomains list
// and returns the domain from the list it matched with.
// The match is either the direct equality of domain names or the input subdomain (e.g. "a.test.com") belongs under a configured top domain ("test.com").
// If the domain does not match CookieDomains, false is returned with the input domain as the second return value.
func (a *Authenticator) matchCookieDomains(domain string) (bool, string) {
	// Remove port
	p := strings.Split(domain, ":")

	if a.config == nil {
		return false, p[0]
	}
	for _, d := range a.config.CookieDomains {
		if d.Match(p[0]) {
			return true, d.Domain
		}
	}
	return false, p[0]
}

func (a *Authenticator) GetBackChannelPath() string {
	path := a.config.Path + "/backchannel-logout"

	return path
}

func (a *Authenticator) IsBackChannelRequest(r *http.Request) bool {
	return r.URL.String() == a.GetBackChannelPath()
}

// Utility methods

// getRequestSchemeHost returns scheme://host part of the request
// Example output: "https://domain.com"
func getRequestSchemeHost(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")

	return fmt.Sprintf("%s://%s", proto, host)
}

// GetRequestURI returns the full request URI with query parameters.
// The path includes the prefix (if stripPrefix middleware was used).
// Example output: "/prefix/path?query=1"
func GetRequestURI(r *http.Request) string {
	prefix := r.Header.Get("X-Forwarded-Prefix")
	uri := r.Header.Get("X-Forwarded-Uri")
	return fmt.Sprintf("%s/%s", strings.TrimRight(prefix, "/"), strings.TrimLeft(uri, "/"))
}

// GetRequestURL returns full requst URL scheme://host/uri with query params
// Example output: "https://domain.com/prefix/path?query=1"
func GetRequestURL(r *http.Request) string {
	return fmt.Sprintf("%s%s", getRequestSchemeHost(r), GetRequestURI(r))
}
