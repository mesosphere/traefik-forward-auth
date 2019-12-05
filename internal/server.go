package tfa

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/containous/traefik/pkg/rules"
	"github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	impersonateUserHeader  = "Impersonate-User"
	impersonateGroupHeader = "Impersonate-Group"
)

type Server struct {
	router *rules.Router
}

func NewServer() *Server {
	s := &Server{}
	s.buildRoutes()
	return s
}

func (s *Server) buildRoutes() {
	var err error
	s.router, err = rules.NewRouter()
	if err != nil {
		log.Fatal(err)
	}

	// Let's build a router
	for name, rule := range config.Rules {
		if rule.Action == "allow" {
			s.router.AddRoute(rule.formattedRule(), 1, s.AllowHandler(name))
		} else {
			s.router.AddRoute(rule.formattedRule(), 1, s.AuthHandler(name))
		}
	}

	// Add callback handler
	s.router.Handle(config.Path, s.AuthCallbackHandler())

	// Add a default handler
	if config.DefaultAction == "allow" {
		s.router.NewRoute().Handler(s.AllowHandler("default"))
	} else {
		s.router.NewRoute().Handler(s.AuthHandler("default"))
	}
}

func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	logger := log.WithFields(logrus.Fields{
		"X-Forwarded-Method": r.Header.Get("X-Forwarded-Method"),
		"X-Forwarded-Proto":  r.Header.Get("X-Forwarded-Proto"),
		"X-Forwarded-Host":   r.Header.Get("X-Forwarded-Host"),
		"X-Forwarded-Prefix": r.Header.Get("X-Forwarded-Prefix"),
		"X-Forwarded-Uri":    r.Header.Get("X-Forwarded-Uri"),
	})

	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")
	r.URL, _ = url.Parse(GetUriPath(r))

	if config.AuthHost == "" || len(config.CookieDomains) > 0 || r.Host == config.AuthHost {
		s.router.ServeHTTP(w, r)
	} else {
		// Redirect the client to the authHost.

		url := r.URL
		url.Scheme = r.Header.Get("X-Forwarded-Proto")
		url.Host = config.AuthHost
		logger.Debug("Redirect to %v", url.String())
		http.Redirect(w, r, url.String(), 307)
	}
}

// Handler that allows requests
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, rule, "Allow request")
		w.WriteHeader(200)
	}
}

// Authenticate requests
func (s *Server) AuthHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, rule, "Authenticate request")

		// Get auth cookie
		c, err := r.Cookie(config.CookieName)
		if err != nil {
			s.notAuthenticated(logger, w, r)
			return
		}

		// Validate cookie
		email, groups, err := ValidateCookie(r, c)
		if err != nil {
			if err.Error() == "Cookie has expired" {
				logger.Info("Cookie has expired")
				s.notAuthenticated(logger, w, r)
			} else {
				logger.Errorf("Invalid cookie: %v", err)
				http.Error(w, "Not authorized", 401)
			}
			return
		}

		// Validate user
		valid := ValidateEmail(email)
		if !valid {
			logger.WithFields(logrus.Fields{
				"email": email,
			}).Errorf("Invalid email")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Valid request
		logger.Debugf("Allow request from %s", email)
		w.Header().Set("X-Forwarded-User", email)

		if config.EnableImpersonation {
			// Set minimal impersonation headers
			logger.Debug("setting authorization token and impersonation headers: ", email)
			w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", config.ServiceAccountToken))
			w.Header().Set(impersonateUserHeader, email)
			w.Header().Set(impersonateGroupHeader, groups)
		}
		w.WriteHeader(200)
	}
}

// Handle auth callback
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "default", "Handling callback")

		// Check for CSRF cookie
		c, err := r.Cookie(config.CSRFCookieName)
		if err != nil {
			logger.Warnf("Missing CSRF cookie: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate state
		valid, redirect, err := ValidateCSRFCookie(r, c)
		if !valid {
			logger.Warnf("Error validating CSRF cookie: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, ClearCSRFCookie(r))

		provider := config.OIDCProvider

		oauth2Config := oauth2.Config{
			ClientID:     config.ClientId,
			ClientSecret: config.ClientSecret,
			RedirectURL:  redirectUri(r),
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}

		// Exchange code for token
		oauth2Token, err := oauth2Config.Exchange(config.OIDCContext, r.URL.Query().Get("code"))
		if err != nil {
			logger.Warnf("failed to exchange token: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			logger.Warnf("missing ID token: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		// Parse and verify ID Token payload.
		verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientId})
		idToken, err := verifier.Verify(config.OIDCContext, rawIDToken)
		if err != nil {
			logger.Warnf("failed to verify token: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		// Extract custom claims
		var claims struct {
			Name     string   `json:"name"`
			Email    string   `json:"email"`
			Verified bool     `json:"email_verified"`
			Groups   []string `json:"groups"`
		}
		if err := idToken.Claims(&claims); err != nil {
			logger.Warnf("failed to extract claims: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		// Generate cookies
		http.SetCookie(w, MakeIDCookie(r, claims.Email, claims.Groups))
		logger.WithFields(logrus.Fields{
			"user": claims.Email,
		}).Infof("Generated auth cookie")

		// If name is empty or whitespace, use email address for name
		name := claims.Name
		if strings.TrimSpace(name) == "" {
			name = claims.Email
		}

		http.SetCookie(w, MakeNameCookie(r, name))
		logger.WithFields(logrus.Fields{
			"name": claims.Name,
		}).Infof("Generated name cookie")

		// Redirect
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

func (s *Server) notAuthenticated(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) {
	// Redirect if request accepts HTML. Fail if request is AJAX, image, etc
	acceptHeader := r.Header.Get("Accept")
	acceptParts := strings.Split(acceptHeader, ",")
	for i, acceptPart := range acceptParts {
		format := strings.Trim(strings.SplitN(acceptPart, ";", 2)[0], " ")
		if format == "text/html" || (i == 0 && format == "*/*") {
			s.authRedirect(logger, w, r)
			return
		}
	}
	logger.Warnf("Non-HTML request: %v", acceptHeader)
	http.Error(w, "Authentication expired. Reload page to re-authenticate.", 401)
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) {
	// Error indicates no cookie, generate nonce
	err, nonce := Nonce()
	if err != nil {
		logger.Errorf("Error generating nonce, %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	http.SetCookie(w, MakeCSRFCookie(r, nonce))
	logger.Debug("Set CSRF cookie and redirect to OIDC login")

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientId,
		ClientSecret: config.ClientSecret,
		RedirectURL:  redirectUri(r),
		Endpoint:     config.OIDCProvider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	state := fmt.Sprintf("%s:%s", nonce, returnUrl(r))

	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)

	return
}

func (s *Server) logger(r *http.Request, rule, msg string) *logrus.Entry {
	// Create logger
	logger := log.WithFields(logrus.Fields{
		"source_ip": r.Header.Get("X-Forwarded-For"),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"rule":    rule,
		"headers": r.Header,
	}).Debug(msg)

	return logger
}
