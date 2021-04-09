package authentication

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

	"github.com/mesosphere/traefik-forward-auth/internal/configuration"
)

type Authenticator struct {
	config *configuration.Config
}

func NewAuthenticator(config *configuration.Config) *Authenticator {
	return &Authenticator{config}
}

// Request Validation

// Cookie = hash(secret, cookie domain, email, expires)|expires|email|groups
func (a *Authenticator) ValidateCookie(r *http.Request, c *http.Cookie) (string, error) {
	parts := strings.Split(c.Value, "|")

	if len(parts) != 3 {
		return "", errors.New("invalid cookie format")
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("unable to decode cookie mac")
	}

	expectedSignature := a.cookieSignature(r, parts[2], parts[1])
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

// Validate email
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

// Get oauth redirect uri
func (a *Authenticator) RedirectUri(r *http.Request) string {
	if use, _ := a.useAuthDomain(r); use {
		proto := r.Header.Get("X-Forwarded-Proto")
		return fmt.Sprintf("%s://%s%s", proto, a.config.AuthHost, a.config.Path)
	}

	return fmt.Sprintf("%s%s", redirectBase(r), a.config.Path)
}

// Should we use auth host + what it is
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

// Create an auth cookie
func (a *Authenticator) MakeIDCookie(r *http.Request, email string) *http.Cookie {
	expires := a.cookieExpiry()
	mac := a.cookieSignature(r, email, fmt.Sprintf("%d", expires.Unix()))
	value := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), email)

	return &http.Cookie{
		Name:     a.config.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   a.GetCookieDomain(r),
		HttpOnly: true,
		Secure:   !a.config.InsecureCookie,
		Expires:  expires,
	}
}

// Create a name cookie
func (a *Authenticator) MakeNameCookie(r *http.Request, name string) *http.Cookie {
	expires := a.cookieExpiry()

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

// Make a CSRF cookie (used during login only)
func (a *Authenticator) MakeCSRFCookie(r *http.Request, nonce string) *http.Cookie {
	return &http.Cookie{
		Name:     a.config.CSRFCookieName,
		Value:    nonce,
		Path:     "/",
		Domain:   a.csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !a.config.InsecureCookie,
		Expires:  a.cookieExpiry(),
	}
}

// Create a cookie to clear csrf cookie
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

// Validate the csrf cookie against state
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

func Nonce() (error, string) {
	// Make nonce
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return err, ""
	}

	return nil, fmt.Sprintf("%x", nonce)
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

// Return matching cookie domain if exists
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

// Create cookie hmac
func (a *Authenticator) cookieSignature(r *http.Request, email, expires string) string {
	hash := hmac.New(sha256.New, a.config.Secret)
	hash.Write([]byte(a.GetCookieDomain(r)))
	hash.Write([]byte(email))
	hash.Write([]byte(expires))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// Get cookie expirary
func (a *Authenticator) cookieExpiry() time.Time {
	return time.Now().Local().Add(a.config.Lifetime)
}

// Utility methods

// Get the redirect base
func redirectBase(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")

	return fmt.Sprintf("%s://%s", proto, host)
}

func GetUriPath(r *http.Request) string {
	prefix := r.Header.Get("X-Forwarded-Prefix")
	uri := r.Header.Get("X-Forwarded-Uri")
	return fmt.Sprintf("%s/%s", strings.TrimRight(prefix, "/"), strings.TrimLeft(uri, "/"))
}

// // Return url
func ReturnUrl(r *http.Request) string {
	return fmt.Sprintf("%s%s", redirectBase(r), GetUriPath(r))
}
