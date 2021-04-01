package authentication

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/mesosphere/traefik-forward-auth/internal/configuration"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
)

type Authenticator struct {
	config *configuration.Config
}

func NewAuthenticator(config *configuration.Config) *Authenticator {
	return &Authenticator{config}
}

// SessionCookie is a structure holding session cookie data
type SessionCookie struct {
	EMail   string
	Groups  []string
	IDToken string
}

// Request Validation

// ValidateSessionCookie validates the session cookie in the request and returns the decoded session data
func (a *Authenticator) ValidateSessionCookie(r *http.Request, c *http.Cookie) (*SessionCookie, error) {
	sc := securecookie.New([]byte(a.config.SecretString), []byte(a.config.EncryptionKeyString)).MaxAge(a.config.CookieMaxAge())

	var data SessionCookie

	err := sc.Decode(a.config.CookieName, c.Value, &data)
	if err != nil {
		return nil, err
	}

	return &data, err
}

// ValidateEmail validates that the provided email is valid which is true in any of these:
// - whitelist and no domainsWhitelist are empty
// - email part after '@' matches one of the domain listed in the domainsWhitelist
// - email is listed in the emailWhitelist
func (a *Authenticator) ValidateEmail(email string, emailWhitelist, domainWhitelist []string) bool {
	if len(emailWhitelist) > 0 || len(domainWhitelist) > 0 {
		for _, whitelist := range emailWhitelist {
			if email == whitelist {
				return true
			}
		}

		parts := strings.Split(email, "@")
		for _, domain := range domainWhitelist {
			if len(parts) >= 2 && domain == parts[1] {
				return true
			}
		}
		return false
	}

	return true // both whitelists empty
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
func (a *Authenticator) GetRequestURI(r *http.Request) string {
	prefix := r.Header.Get("X-Forwarded-Prefix")
	uri := r.Header.Get("X-Forwarded-Uri")
	return fmt.Sprintf("%s/%s", strings.TrimRight(prefix, "/"), strings.TrimLeft(uri, "/"))
}

// GetRequestURL returns full requst URL scheme://host/uri with query params
// Example output: "https://domain.com/prefix/path?query=1"
func (a *Authenticator) GetRequestURL(r *http.Request) string {
	return fmt.Sprintf("%s%s", getRequestSchemeHost(r), a.GetRequestURI(r))
}

// ComposeRedirectURI generates oauth redirect uri to return to from the OAuth2 provider
// Either as request-scheme://request-host/<path>
// Or, if auth domain configured and usable: request-scheme://<authHost>/<path>
// Cookiedomains are consulted to decide whether to use auth domain
func (a *Authenticator) ComposeRedirectURI(r *http.Request) string {
	authHost := a.config.AuthHost
	path := a.config.Path
	if use, _ := a.useAuthDomain(r); use {
		scheme := r.Header.Get("X-Forwarded-Proto")
		return fmt.Sprintf("%s://%s%s", scheme, authHost, path)
	}

	return fmt.Sprintf("%s%s", getRequestSchemeHost(r), path)
}

// useAuthDomain decides whether the host of the forwarded request
// matches the configured authHost and whether we can configure cookies for the AuthHost
// If it does, the function returns true and the top-level domain from the config we can use
func (a *Authenticator) useAuthDomain(r *http.Request) (bool, string) {
	authHost := a.config.AuthHost
	if authHost == "" {
		return false, ""
	}

	// Does the request match a given cookie domain?
	reqMatch, reqHost := a.matchCookieDomains(r.Header.Get("X-Forwarded-Host"))

	// Do any of the auth hosts match a cookie domain?
	authMatch, authHost := a.matchCookieDomains(authHost)

	// We need both to match the same domain
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// Cookie methods

// MakeSessionCookie creates an authenticated and encrypted cookie holding session data
func (a *Authenticator) MakeSessionCookie(r *http.Request, data SessionCookie) (*http.Cookie, error) {
	sc := securecookie.New([]byte(a.config.SecretString), []byte(a.config.EncryptionKeyString)).MaxAge(a.config.CookieMaxAge())

	encoded, err := sc.Encode(a.config.CookieName, data)
	if err != nil {
		return nil, err
	}

	cookie := &http.Cookie{
		Name:     a.config.CookieName,
		Value:    encoded,
		Path:     "/",
		Domain:   a.CookieDomain(r),
		HttpOnly: true,
		Secure:   !a.config.InsecureCookie,
		Expires:  a.config.CookieExpiry(),
	}

	return cookie, nil
}

// MakeNameCookie creates a name cookie
func (a *Authenticator) MakeNameCookie(r *http.Request, name string) *http.Cookie {
	return &http.Cookie{
		Name:     a.config.UserCookieName,
		Value:    name,
		Path:     "/",
		Domain:   a.CookieDomain(r),
		HttpOnly: false,
		Secure:   false,
		Expires:  a.config.CookieExpiry(),
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
func (a *Authenticator) ValidateCSRFCookie(r *http.Request, c *http.Cookie) (bool, string, error) {
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
func (a *Authenticator) GenerateNonce() (string, error) {
	// Make nonce
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", nonce), nil
}

// CookieDomain
func (a *Authenticator) CookieDomain(r *http.Request) string {
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
