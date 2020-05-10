package tfa

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
)

// sessionCookie is a structure holding session cookie data
type sessionCookie struct {
	EMail   string
	Groups  []string
	IDToken string
}

// Request Validation

// validateSessionCookie validates the session cookie in the request and returns the decoded session data
func validateSessionCookie(r *http.Request, c *http.Cookie, config *Config) (*sessionCookie, error) {
	sc := securecookie.New([]byte(config.SecretString), []byte(config.EncryptionKeyString)).MaxAge(config.CookieMaxAge())

	var data sessionCookie

	err := sc.Decode(config.CookieName, c.Value, &data)
	if err != nil {
		return nil, err
	}

	return &data, err
}

// validateEmail validates that the provided email is valid which is true in any of these:
// - whitelist and no domainsWhitelist are empty
// - email part after '@' matches one of the domain listed in the domainsWhitelist
// - email is listed in the emailWhitelist
func validateEmail(email string, emailWhitelist, domainWhitelist []string) bool {
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

// getRequestURI returns the full request URI with query parameters.
// The path includes the prefix (if stripPrefix middleware was used).
// Example output: "/prefix/path?query=1"
func getRequestURI(r *http.Request) string {
	prefix := r.Header.Get("X-Forwarded-Prefix")
	uri := r.Header.Get("X-Forwarded-Uri")
	return fmt.Sprintf("%s/%s", strings.TrimRight(prefix, "/"), strings.TrimLeft(uri, "/"))
}

// getRequestURL returns full requst URL scheme://host/uri with query params
// Example output: "https://domain.com/prefix/path?query=1"
func getRequestURL(r *http.Request) string {
	return fmt.Sprintf("%s%s", getRequestSchemeHost(r), getRequestURI(r))
}

// composeRedirectURI generates oauth redirect uri to return to from the OAuth2 provider
// Either as request-scheme://request-host/<path>
// Or, if auth domain configured and usable: request-scheme://<authHost>/<path>
// Cookiedomains are consulted to decide whether to use auth domain
func composeRedirectURI(r *http.Request, authHost, path string, cookieDomains []CookieDomain) string {
	if use, _ := useAuthDomain(r, authHost, cookieDomains); use {
		scheme := r.Header.Get("X-Forwarded-Proto")
		return fmt.Sprintf("%s://%s%s", scheme, authHost, path)
	}

	return fmt.Sprintf("%s%s", getRequestSchemeHost(r), path)
}

// useAuthDomain decides whether the host of the forwarded request
// matches the configured authHost and whether we can configure cookies for the AuthHost
// If it does, the function returns true and the top-level domain from the config we can use
func useAuthDomain(r *http.Request, authHost string, cookieDomains []CookieDomain) (bool, string) {
	if authHost == "" {
		return false, ""
	}

	// Does the request match a given cookie domain?
	reqMatch, reqHost := matchCookieDomains(r.Header.Get("X-Forwarded-Host"), cookieDomains)

	// Do any of the auth hosts match a cookie domain?
	authMatch, authHost := matchCookieDomains(authHost, cookieDomains)

	// We need both to match the same domain
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// Cookie methods

// makeSessionCookie creates an authenticated and encrypted cookie holding session data
func makeSessionCookie(r *http.Request, config *Config, data sessionCookie) *http.Cookie {
	sc := securecookie.New([]byte(config.SecretString), []byte(config.EncryptionKeyString)).MaxAge(config.CookieMaxAge())

	encoded, err := sc.Encode(config.CookieName, data)
	if err != nil {
		return nil
	}

	return &http.Cookie{
		Name:     config.CookieName,
		Value:    encoded,
		Path:     "/",
		Domain:   cookieDomain(r, config.CookieDomains),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  config.CookieExpiry(),
	}
}

// makeNameCookie creates a name cookie
func makeNameCookie(r *http.Request, config *Config, name string) *http.Cookie {
	return &http.Cookie{
		Name:     config.UserCookieName,
		Value:    name,
		Path:     "/",
		Domain:   cookieDomain(r, config.CookieDomains),
		HttpOnly: false,
		Secure:   false,
		Expires:  config.CookieExpiry(),
	}
}

// makeCSRFCookie creates a CSRF cookie (used during login only)
func makeCSRFCookie(r *http.Request, config *Config, nonce string) *http.Cookie {
	return &http.Cookie{
		Name:     config.CSRFCookieName,
		Value:    nonce,
		Path:     "/",
		Domain:   csrfCookieDomain(r, config.AuthHost, config.CookieDomains),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  config.CookieExpiry(),
	}
}

// clearCSRFCookie clears the csrf cookie
func clearCSRFCookie(r *http.Request, config *Config) *http.Cookie {
	return &http.Cookie{
		Name:     config.CSRFCookieName,
		Value:    "",
		Path:     "/",
		Domain:   csrfCookieDomain(r, config.AuthHost, config.CookieDomains),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// validateCSRFCookie validates the csrf cookie against state
func validateCSRFCookie(r *http.Request, c *http.Cookie) (bool, string, error) {
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

// generateNonce generates a random nonce string
func generateNonce() (string, error) {
	// Make nonce
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", nonce), nil
}

// Cookie domain
func cookieDomain(r *http.Request, cookieDomains []CookieDomain) string {
	host := r.Header.Get("X-Forwarded-Host")

	// Check if any of the given cookie domains matches
	_, domain := matchCookieDomains(host, cookieDomains)
	return domain
}

// Cookie domain
func csrfCookieDomain(r *http.Request, authHost string, cookieDomains []CookieDomain) string {
	var host string
	if use, domain := useAuthDomain(r, authHost, cookieDomains); use {
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
func matchCookieDomains(domain string, cookieDomains []CookieDomain) (bool, string) {
	// Remove port
	p := strings.Split(domain, ":")

	for _, d := range cookieDomains {
		if d.Match(p[0]) {
			return true, d.Domain
		}
	}

	return false, p[0]
}

// Cookie Domain

// CookieDomain represents a top-level cookie domain and helper functions on it
type CookieDomain struct {
	Domain       string `description:"TEST1"`
	DomainLen    int    `description:"TEST2"`
	SubDomain    string `description:"TEST3"`
	SubDomainLen int    `description:"TEST4"`
}

func newCookieDomain(domain string) *CookieDomain {
	return &CookieDomain{
		Domain:       domain,
		DomainLen:    len(domain),
		SubDomain:    fmt.Sprintf(".%s", domain),
		SubDomainLen: len(domain) + 1,
	}
}

// Match returns true if host matches the CookieDomain or is a subdomain of it
func (c *CookieDomain) Match(host string) bool {
	// Exact domain match?
	if host == c.Domain {
		return true
	}

	// Subdomain match?
	if len(host) >= c.SubDomainLen && host[len(host)-c.SubDomainLen:] == c.SubDomain {
		return true
	}

	return false
}

// UnmarshalFlag unmarshals the CookieDomain from the flag string
func (c *CookieDomain) UnmarshalFlag(value string) error {
	*c = *newCookieDomain(value)
	return nil
}

// MarshalFlag marshals the CookieDomain into a flag string
func (c *CookieDomain) MarshalFlag() (string, error) {
	return c.Domain, nil
}

// Legacy support for comma separated list of cookie domains

// CookieDomains holds a list of cookie domains
type CookieDomains []CookieDomain

// UnmarshalFlag unmarshals the CookieDomains from the flag string
func (c *CookieDomains) UnmarshalFlag(value string) error {
	if len(value) > 0 {
		for _, d := range strings.Split(value, ",") {
			cookieDomain := newCookieDomain(d)
			*c = append(*c, *cookieDomain)
		}
	}
	return nil
}

// MarshalFlag marshals the CookieDomain into a flag string
func (c *CookieDomains) MarshalFlag() (string, error) {
	var domains []string
	for _, d := range *c {
		domains = append(domains, d.Domain)
	}
	return strings.Join(domains, ","), nil
}
