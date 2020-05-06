package tfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Request Validation

// validateCookie validates the ID cookie in the request
// IDCookie = hash(secret, cookie domain, email, expires)|expires|email
func validateCookie(r *http.Request, c *http.Cookie) (string, error) {
	parts := strings.Split(c.Value, "|")

	if len(parts) != 3 {
		return "", errors.New("invalid cookie format")
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("unable to decode cookie mac")
	}

	expectedSignature := cookieSignature(r, parts[2], parts[1])
	expected, err := base64.URLEncoding.DecodeString(expectedSignature)
	if err != nil {
		return "", errors.New("unable to generate mac")
	}

	// Valid token?
	if !hmac.Equal(mac, expected) {
		return "", errors.New("invalid cookie mac")
	}

	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errors.New("unable to parse cookie expiry")
	}

	// Has it expired?
	if time.Unix(expires, 0).Before(time.Now()) {
		return "", errors.New("cookie has expired")
	}

	// Looks valid
	return parts[2], nil
}

// validateEmail validates that the provided email ends with one of the configured Domains or is part of the configured Whitelist.
// Also returns true if there is no Whitelist and no Domains configured.
func validateEmail(email string) bool {
	if len(config.Whitelist) > 0 || len(config.Domains) > 0 {
		for _, whitelist := range config.Whitelist {
			if email == whitelist {
				return true
			}
		}

		parts := strings.Split(email, "@")
		for _, domain := range config.Domains {
			if len(parts) >= 2 && domain == parts[1] {
				return true
			}
		}
		return false
	}
	return true
}

// Utility methods

// getRequestSchemeHost returns scheme://host part of the request
func getRequestSchemeHost(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")

	return fmt.Sprintf("%s://%s", proto, host)
}

// getRequestPath returns request path without trailing slash and query parameters.
// The path includes prefix (i.e. if StripPrefix middleware was used, this prefix is not stipped here)
func getRequestPath(r *http.Request) string {
	prefix := r.Header.Get("X-Forwarded-Prefix")
	uri := r.Header.Get("X-Forwarded-Uri")
	return fmt.Sprintf("%s/%s", strings.TrimRight(prefix, "/"), strings.TrimLeft(uri, "/"))
}

// getRequestURL returns full requst URL scheme://host/path without query params
func getRequestURL(r *http.Request) string {
	return fmt.Sprintf("%s%s", getRequestSchemeHost(r), getRequestPath(r))
}

// composeRedirectURI generates oauth redirect uri to return to from the OAuth2 provider
func composeRedirectURI(r *http.Request) string {
	if use, _ := useAuthDomain(r); use {
		scheme := r.Header.Get("X-Forwarded-Proto")
		return fmt.Sprintf("%s://%s%s", scheme, config.AuthHost, config.Path)
	}

	return fmt.Sprintf("%s%s", getRequestSchemeHost(r), config.Path)
}

// useAuthDomain decides whether the host of the forwarded request
// matches the configured AuthHost and whether we can configure cookies for the AuthHost
// If it does, the function returns true and the top-level domain from the config we can use
func useAuthDomain(r *http.Request) (bool, string) {
	if config.AuthHost == "" {
		return false, ""
	}

	// Does the request match a given cookie domain?
	reqMatch, reqHost := matchCookieDomains(r.Header.Get("X-Forwarded-Host"))

	// Do any of the auth hosts match a cookie domain?
	authMatch, authHost := matchCookieDomains(config.AuthHost)

	// We need both to match the same domain
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// Cookie methods

// makeIDCookie creates an auth cookie
func makeIDCookie(r *http.Request, email string) *http.Cookie {
	expires := cookieExpiry()
	mac := cookieSignature(r, email, fmt.Sprintf("%d", expires.Unix()))
	value := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), email)

	return &http.Cookie{
		Name:     config.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   cookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  expires,
	}
}

// makeNameCookie creates a name cookie
func makeNameCookie(r *http.Request, name string) *http.Cookie {
	expires := cookieExpiry()

	return &http.Cookie{
		Name:     config.UserCookieName,
		Value:    name,
		Path:     "/",
		Domain:   cookieDomain(r),
		HttpOnly: false,
		Secure:   false,
		Expires:  expires,
	}
}

// makeCSRFCookie creates a CSRF cookie (used during login only)
func makeCSRFCookie(r *http.Request, nonce string) *http.Cookie {
	return &http.Cookie{
		Name:     config.CSRFCookieName,
		Value:    nonce,
		Path:     "/",
		Domain:   csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  cookieExpiry(),
	}
}

// clearCSRFCookie clears the csrf cookie
func clearCSRFCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     config.CSRFCookieName,
		Value:    "",
		Path:     "/",
		Domain:   csrfCookieDomain(r),
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
func cookieDomain(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")

	// Check if any of the given cookie domains matches
	_, domain := matchCookieDomains(host)
	return domain
}

// Cookie domain
func csrfCookieDomain(r *http.Request) string {
	var host string
	if use, domain := useAuthDomain(r); use {
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
func matchCookieDomains(domain string) (bool, string) {
	// Remove port
	p := strings.Split(domain, ":")

	for _, d := range config.CookieDomains {
		if d.Match(p[0]) {
			return true, d.Domain
		}
	}

	return false, p[0]
}

// cookieSignature create a cookie hmac
func cookieSignature(r *http.Request, email, expires string) string {
	hash := hmac.New(sha256.New, config.Secret)
	hash.Write([]byte(cookieDomain(r)))
	hash.Write([]byte(email))
	hash.Write([]byte(expires))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// cookieExpiry returns the expiration time, Lifetime duration since now
func cookieExpiry() time.Time {
	return time.Now().Local().Add(config.Lifetime)
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
