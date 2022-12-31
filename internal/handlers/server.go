package handlers

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"

	"github.com/containous/traefik/pkg/rules"
	"github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	api "github.com/turnly/oauth-middleware/internal/api"
	"github.com/turnly/oauth-middleware/internal/authentication"
	"github.com/turnly/oauth-middleware/internal/configuration"
	log "github.com/turnly/oauth-middleware/internal/log"
	"golang.org/x/oauth2"
)

const (
	impersonateUserHeader  = "Impersonate-User"
	impersonateGroupHeader = "Impersonate-Group"
)

// Server implements the HTTP server handling forwardauth
type Server struct {
	router        *rules.Router
	store         api.StoreInterface
	log           logrus.FieldLogger
	config        *configuration.Config
	authenticator *authentication.Authenticator
}

// NewServer creates a new forwardauth server
func NewServer(store api.StoreInterface, config *configuration.Config) *Server {
	s := &Server{
		log:           log.NewDefaultLogger(config.LogLevel, config.LogFormat),
		config:        config,
		store:         store,
		authenticator: authentication.NewAuthenticator(config),
	}

	s.buildRoutes()
	s.store = store

	return s
}

func (s *Server) buildRoutes() {
	var err error
	s.router, err = rules.NewRouter()
	if err != nil {
		s.log.Fatal(err)
	}

	// Let's build a router
	for name, rule := range s.config.Rules {
		var err error
		if rule.Action == "allow" {
			err = s.router.AddRoute(rule.FormattedRule(), 1, s.AllowHandler(name))
		} else {
			err = s.router.AddRoute(rule.FormattedRule(), 1, s.AuthHandler(name))
		}
		if err != nil {
			panic(fmt.Sprintf("Oops. error while adding route: %v", err))
		}
	}

	s.router.Handle(s.config.Path, s.AuthCallbackHandler())
	s.router.Handle(s.authenticator.GetBackChannelPath(), s.BackChannelLogoutHandler())

	if s.config.DefaultAction == "allow" {
		s.router.NewRoute().Handler(s.AllowHandler("default"))
	} else {
		s.router.NewRoute().Handler(s.AuthHandler("default"))
	}
}

// RootHandler it the main handler (for / path)
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	logger := s.log.WithFields(logrus.Fields{
		"X-Forwarded-Method": r.Header.Get("X-Forwarded-Method"),
		"X-Forwarded-Proto":  r.Header.Get("X-Forwarded-Proto"),
		"X-Forwarded-Host":   r.Header.Get("X-Forwarded-Host"),
		"X-Forwarded-Prefix": r.Header.Get("X-Forwarded-Prefix"),
		"X-Forwarded-Uri":    r.Header.Get("X-Forwarded-Uri"),
	})

	logger.Debug("Processing new request from root handler ...")

	if s.authenticator.IsBackChannelRequest(r) {
		logger.Debug("Processing backchannel request ...")

		s.BackChannelLogoutHandler().ServeHTTP(w, r)
		return
	}

	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")
	r.URL, _ = neturl.Parse(authentication.GetRequestURI(r))

	if s.config.AuthHost == "" || len(s.config.CookieDomains) > 0 || r.Host == s.config.AuthHost {
		logger.Debug("Forwarding request to routers ...")

		s.router.ServeHTTP(w, r)
	} else {
		logger.Debug("Redirecting request to auth host ...")

		// Redirect the client to the authHost.
		url := r.URL
		url.Scheme = r.Header.Get("X-Forwarded-Proto")
		url.Host = s.config.AuthHost

		logger.Infof("Redirecting request to %v ...", url.String())

		http.Redirect(w, r, url.String(), 307)
	}
}

// AllowHandler handles the request as implicit "allow", returning HTTP 200 response to the Traefik
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, rule, "Allow request")
		w.WriteHeader(200)
	}
}

/**
 * OpenID Connect Back-Channel Logout
 * https://openid.net/specs/openid-connect-backchannel-1_0.html
 *
 * Keycloak Backchannel logout URL: http://oauth.turnly.local:4181/_oauth/backchannel-logout
 */
func (s *Server) BackChannelLogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger(r, "default", "OpenID Connect Back-Channel Logout")

		logger.Debug("Got a back-channel logout request, processing ...")

		logoutToken := r.FormValue("logout_token")
		if logoutToken == "" {
			logger.Error("Oops, we got a logout request without a logout_token")

			http.Error(w, "Oops, we got a logout request without a logout_token", 400)
			return
		}

		logger.Debugf("Got a logout request with logout_token: %s", logoutToken)

		verifier := s.config.OIDCProvider.Verifier(&oidc.Config{ClientID: s.config.ClientID, SkipClientIDCheck: true, SkipExpiryCheck: true})
		token, err := verifier.Verify(s.config.OIDCContext, logoutToken)
		if err != nil {
			logger.Errorf("Oops, failed to verify the logout_token: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		var claims map[string]interface{}
		if err := token.Claims(&claims); err != nil {
			logger.Errorf("Oops, failed to parse the logout_token claims: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		logger.Debugf("Got a logout request with claims: %v", claims["sub"].(string))

		w.WriteHeader(200)
	}
}

// AuthHandler handles the request as requiring authentication.
// It validates the existing session, starting a new auth flow if the session is not valid.
// Finally it also performs authorization (if enabled) to ensure the logged-in subject is authorized to perform the request.
func (s *Server) AuthHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, rule, "Authenticate request")

		// Get auth cookie
		c, err := r.Cookie(s.config.CookieName)
		if err != nil {
			s.notAuthenticated(logger, w, r)
			return
		}

		// Validate cookie
		id, err := s.authenticator.ValidateCookie(r, c)
		if err != nil {
			logger.Debugf(fmt.Sprintf("Oops, failed to validate cookie: %v", err.Error()))
			logger.Debugf("Redirecting to IAM for re-authentication ...")
			s.notAuthenticated(logger, w, r)
			return
		}

		// Validate user
		valid := s.authenticator.ValidateEmail(id.Email)
		if !valid {
			logger.WithFields(logrus.Fields{
				"email": id.Email,
			}).Errorf("Oops, failed to validate email: %v", err.Error())

			http.Error(w, "Not authorized", 401)

			return
		}

		// Token forwarding requested now with no token stored in the session, re-auth
		if s.config.ForwardTokenHeaderName != "" && id.Token == "" {
			logger.Debug("Redirecting to IAM for re-authentication because token forwarding enabled and no token stored ...")
			s.notAuthenticated(logger, w, r)
			return
		}

		// Authorize user
		groups, err := s.getGroupsFromSession(r)
		if err != nil {
			logger.Errorf("Oops, failed to get groups from session: %v", err)
			logger.Debug("Redirecting to IAM for re-authentication ...")

			s.notAuthenticated(logger, w, r)
			return
		}

		if groups == nil {
			logger.Debug("Oops, no groups found in session, redirecting to IAM for re-authentication ...")

			s.notAuthenticated(logger, w, r)
			return
		}

		// Valid request
		logger.Debugf("Ahoy, the user is authenticated and authorized, allowing request ... user: %s, groups: %s", id.Email, groups)
		for _, headerName := range s.config.EmailHeaderNames {
			w.Header().Set(headerName, id.Email)
		}

		if s.config.ForwardTokenHeaderName != "" && id.Token != "" {
			w.Header().Add(s.config.ForwardTokenHeaderName, s.config.ForwardTokenPrefix+id.Token)
		}

		w.WriteHeader(200)
	}
}

var removeHeaders = map[string]bool{
	strings.ToLower("Authorization"):        true,
	strings.ToLower(impersonateUserHeader):  true,
	strings.ToLower(impersonateGroupHeader): true,
}

// AuthCallbackHandler handles the request as a callback from authentication provider.
// It validates CSRF, exchanges code-token for id-token and extracts groups from the id-token.
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "default", "Authenticate callback")

		logger.Debug("Processing authentication request callback from IAM ...")

		// Check for CSRF cookie
		c, err := r.Cookie(s.config.CSRFCookieName)
		if err != nil {
			logger.Errorf("Oops, failed to get CSRF cookie: %v", err)

			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate state
		valid, redirect, err := authentication.ValidateCSRFCookie(r, c)
		if !valid {
			logger.Errorf("Oops, failed to validate CSRF cookie: %v", err)

			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, s.authenticator.ClearCSRFCookie(r))

		provider := s.config.OIDCProvider

		// Mapping scope
		var scope []string
		if s.config.Scope != "" {
			scope = []string{s.config.Scope}
		} else {
			scope = []string{oidc.ScopeOpenID, "openid", "profile", "email"}
		}

		oauth2Config := oauth2.Config{
			ClientID:     s.config.ClientID,
			ClientSecret: s.config.ClientSecret,
			RedirectURL:  s.authenticator.ComposeRedirectURI(r),
			Endpoint:     provider.Endpoint(),
			Scopes:       scope,
		}

		// Exchange code for token
		oauth2Token, err := oauth2Config.Exchange(s.config.OIDCContext, r.URL.Query().Get("code"))
		if err != nil {
			logger.Errorf("Oops, a unexpected error occurred while exchanging token: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			logger.Error("Oops, the ID token is missing from the IAM response")
			http.Error(w, "Bad Gateway", 502)
			return
		}

		// Parse and verify ID Token payload.
		verifier := provider.Verifier(&oidc.Config{ClientID: s.config.ClientID})
		idToken, err := verifier.Verify(s.config.OIDCContext, rawIDToken)
		if err != nil {
			logger.Errorf("Oops, a unexpected error occurred while verifying token: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		// Extract custom claims
		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			logger.Errorf("Oops, a unexpected error occurred while extracting claims: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		email, ok := claims["email"]
		if ok {
			token := ""
			if s.config.ForwardTokenHeaderName != "" {
				token = rawIDToken
			}

			// Generate cookies
			c, err := s.authenticator.MakeIDCookie(r, email.(string), token)
			if err != nil {
				logger.Errorf("Oops, a unexpected error occurred while generating cookies: %v", err)
				http.Error(w, "Bad Gateway", 502)
				return
			}

			http.SetCookie(w, c)

			logger.Debugf("Generated ID cookie for user %s", claims["email"].(string))

		} else {
			logger.Warn("Oops, no email claim found in the ID token")
		}

		// If name in null, empty or whitespace, use email address for name
		name, ok := claims["name"]
		if !ok || (ok && strings.TrimSpace(name.(string)) == "") {
			name = email.(string)
		}

		http.SetCookie(w, s.authenticator.MakeNameCookie(r, name.(string)))
		logger.WithFields(logrus.Fields{
			"name": name.(string),
		}).Debugf("Generated name cookie for user %s", claims["email"].(string))

		// Mapping groups
		groups := []string{}
		groupsClaim, ok := claims[s.config.GroupsAttributeName].([]interface{})
		if ok {
			for _, g := range groupsClaim {
				groups = append(groups, g.(string))
			}
		} else {
			logger.Warnf("Oops, no groups claim found in the ID token (GroupsAttributeName: %s)", s.config.GroupsAttributeName)
		}

		if err := s.store.Save(r, w, &api.UserInfo{
			Username: name.(string),
			Email:    email.(string),
			Groups:   groups,
		}); err != nil {
			logger.Errorf("Oops, a unexpected error occurred while saving session: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		// Redirect
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

// notAuthenticated is used to signal the request does not include a valid authentication data.
// If the request came from a browser (having "text/html" in the Accept header), authentication
// redirect is made to start a new auth flow. Otherwise the "Authenticatio expired" message
// is passed as one of the known content-types or as a plain text.
func (s *Server) notAuthenticated(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) {
	bestFormat := ""

	// Redirect if request accepts HTML. Fail if request is AJAX, image, etc
	acceptHeader := r.Header.Get("Accept")
	acceptParts := strings.Split(acceptHeader, ",")

	for i, acceptPart := range acceptParts {
		format := strings.Trim(strings.SplitN(acceptPart, ";", 2)[0], " ")

		if format == "text/html" || (i == 0 && format == "*/*") {
			logger.Debug("This request is from a valid client (browser) and will be redirected to the IAM for authentication, redirecting...")
			s.authRedirect(logger, w, r)
			return
		} else if strings.HasPrefix(format, "application/json") {
			bestFormat = "json"
		} else if strings.HasPrefix(format, "application/xml") {
			bestFormat = "xml"
		}
	}

	logger.Debug("This request is not from a valid client (browser) and will be rejected with a 401 error")

	errStr := "Oops, your authentication has expired or is invalid and you need to re-authenticate."

	if bestFormat == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)

		json.NewEncoder(w).Encode(map[string]string{"error": errStr})
		return
	}

	if bestFormat == "xml" {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(401)

		xml.NewEncoder(w).Encode(map[string]string{"error": errStr})
		return
	}

	http.Error(w, errStr, 401)
}

// authRedirect generates CSRF cookie and redirects to authentication provider to start the authentication flow.
func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) {
	// Error indicates no cookie, generate nonce
	nonce, err := authentication.GenerateNonce()
	if err != nil {
		logger.Errorf("Oops, a unexpected error occurred while generating nonce: %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	http.SetCookie(w, s.authenticator.MakeCSRFCookie(r, nonce))
	logger.Debug("Sending CSRF cookie and a redirect to OIDC login")

	// Mapping scope
	var scope []string
	if s.config.Scope != "" {
		scope = []string{s.config.Scope}
	} else {
		scope = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
	}

	logger.Debugf("The scope used for the authentication is: %s", scope)

	// clear existing claims session
	if err = s.store.Clear(r, w); err != nil {
		logger.Errorf("Oops, error clearing session: %v", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     s.config.ClientID,
		ClientSecret: s.config.ClientSecret,
		RedirectURL:  s.authenticator.ComposeRedirectURI(r),
		Endpoint:     s.config.OIDCProvider.Endpoint(),
		Scopes:       scope,
	}

	state := fmt.Sprintf("%s:%s", nonce, authentication.GetRequestURL(r))

	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)

	return
}

// logger provides a new logger enriched with request info
func (s *Server) logger(r *http.Request, rule, msg string) *logrus.Entry {
	// Create logger
	logger := s.log.WithFields(logrus.Fields{
		"source_ip": r.Header.Get("X-Forwarded-For"),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"rule":    rule,
		"headers": r.Header,
	}).Debug(msg)

	return logger
}

// getGroupsFromSession returns list of groups present in the session
func (s *Server) getGroupsFromSession(r *http.Request) ([]string, error) {
	userInfo, err := s.store.Get(r)
	if err != nil {
		return nil, err
	}
	return userInfo.Groups, nil
}
