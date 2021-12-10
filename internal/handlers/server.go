package handlers

import (
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"

	"github.com/mesosphere/traefik-forward-auth/internal/api/storage/v1alpha1"
	"github.com/mesosphere/traefik-forward-auth/internal/authentication"
	"github.com/mesosphere/traefik-forward-auth/internal/configuration"

	"github.com/coreos/go-oidc"
	"github.com/mesosphere/traefik-forward-auth/internal/authorization/rbac"
	"github.com/sirupsen/logrus"
	"github.com/traefik/traefik/v2/pkg/rules"
	"golang.org/x/oauth2"
	"k8s.io/client-go/kubernetes"

	"github.com/mesosphere/traefik-forward-auth/internal/authorization"
	internallog "github.com/mesosphere/traefik-forward-auth/internal/log"
)

const (
	impersonateUserHeader  = "Impersonate-User"
	impersonateGroupHeader = "Impersonate-Group"
)

type Server struct {
	router        *rules.Router
	userinfo      v1alpha1.UserInfoInterface
	authorizer    authorization.Authorizer
	log           logrus.FieldLogger
	config        *configuration.Config
	authenticator *authentication.Authenticator
}

func NewServer(userinfo v1alpha1.UserInfoInterface, clientset kubernetes.Interface, config *configuration.Config) *Server {
	s := &Server{
		log:           internallog.NewDefaultLogger(config.LogLevel, config.LogFormat),
		config:        config,
		userinfo:      userinfo,
		authenticator: authentication.NewAuthenticator(config),
	}

	s.buildRoutes()
	s.userinfo = userinfo
	if config.EnableRBAC {
		s.authorizer = rbac.NewRBACAuthorizer(clientset)
	}
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
			panic(fmt.Sprintf("could not add route: %v", err))
		}
	}

	// Add callback handler
	s.router.Handle(s.config.Path, s.AuthCallbackHandler())

	// Add a default handler
	if s.config.DefaultAction == "allow" {
		s.router.NewRoute().Handler(s.AllowHandler("default"))
	} else {
		s.router.NewRoute().Handler(s.AuthHandler("default"))
	}
}

func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	logger := s.log.WithFields(logrus.Fields{
		"X-Forwarded-Method": r.Header.Get("X-Forwarded-Method"),
		"X-Forwarded-Proto":  r.Header.Get("X-Forwarded-Proto"),
		"X-Forwarded-Host":   r.Header.Get("X-Forwarded-Host"),
		"X-Forwarded-Prefix": r.Header.Get("X-Forwarded-Prefix"),
		"X-Forwarded-Uri":    r.Header.Get("X-Forwarded-Uri"),
	})

	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")
	r.URL, _ = neturl.Parse(authentication.GetUriPath(r))

	if s.config.AuthHost == "" || len(s.config.CookieDomains) > 0 || r.Host == s.config.AuthHost {
		s.router.ServeHTTP(w, r)
	} else {
		// Redirect the client to the authHost.
		url := r.URL
		url.Scheme = r.Header.Get("X-Forwarded-Proto")
		url.Host = s.config.AuthHost
		logger.Debugf("Redirect to %v", url.String())
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
		c, err := r.Cookie(s.config.CookieName)
		if err != nil {
			s.notAuthenticated(logger, w, r)
			return
		}

		// Validate cookie
		email, err := s.authenticator.ValidateCookie(r, c)
		if err != nil {
			logger.Info(fmt.Sprintf("cookie validaton failure: %s", err.Error()))
			s.notAuthenticated(logger, w, r)
			return
		}

		// Validate user
		valid := s.authenticator.ValidateEmail(email)
		if !valid {
			logger.WithFields(logrus.Fields{
				"email": email,
			}).Errorf("Invalid email")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Authorize user
		groups, err := s.getGroupsFromSession(r)
		if err != nil {
			logger.Errorf("error getting groups from session: %v", err)
			s.notAuthenticated(logger, w, r)
			return
		}

		if groups == nil {
			logger.Info("groups session data is missing, re-authenticating")
			s.notAuthenticated(logger, w, r)
			return
		}

		if s.config.EnableRBAC && !s.authzIsBypassed(r) {
			kubeUserInfo := s.getModifiedUserInfo(email, groups)

			logger.Debugf("authorizing user: %s, groups: %s", kubeUserInfo.Name, kubeUserInfo.Groups)
			authorized, err := s.authorizer.Authorize(kubeUserInfo, r.Method, r.URL.Path)
			if err != nil {
				logger.Errorf("error while authorizing %s: %v", kubeUserInfo, err)
				http.Error(w, "Bad Gateway", 502)
				return
			}

			if !authorized {
				logger.Infof("user %s for is not authorized to `%s` in %s", kubeUserInfo.GetName(), r.Method, r.URL.Path)
				http.Error(w, "Not Authorized", 401)
				return
			}
			logger.Infof("user %s is authorized to `%s` in %s", kubeUserInfo.GetName(), r.Method, r.URL.Path)
		}

		// Valid request
		logger.Debugf("Allow request from %s", email)
		for _, headerName := range s.config.EmailHeaderNames {
			w.Header().Set(headerName, email)
		}

		if s.config.EnableImpersonation {
			// Set impersonation headers
			logger.Debug(fmt.Sprintf("setting authorization token and impersonation headers: email: %s, groups: %s", email, groups))
			w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", s.config.ServiceAccountToken))
			w.Header().Set(impersonateUserHeader, email)
			w.Header().Set(impersonateGroupHeader, "system:authenticated")
			for _, group := range groups {
				w.Header().Add(impersonateGroupHeader, fmt.Sprintf("%s%s", s.config.GroupClaimPrefix, group))
			}
			w.Header().Set("Connection", cleanupConnectionHeader(w.Header().Get("Connection")))
		}
		w.WriteHeader(200)
	}
}

var removeHeaders = map[string]bool{
	strings.ToLower("Authorization"):        true,
	strings.ToLower(impersonateUserHeader):  true,
	strings.ToLower(impersonateGroupHeader): true,
}

// Traefik correctly removes any headers listed in the Connection header, but
// because it removes headers after forward auth has run, a specially crafted
// request can forward to the backend with the forward auth headers removed.
// Remove forward auth headers from the Connection header to ensure that they
// get passed to the backend.
func cleanupConnectionHeader(original string) string {
	headers := strings.Split(original, ",")
	passThrough := make([]string, 0, len(headers))
	for _, header := range headers {
		if remove := removeHeaders[strings.ToLower(strings.TrimSpace(header))]; !remove {
			passThrough = append(passThrough, header)
		}
	}
	return strings.TrimSpace(strings.Join(passThrough, ","))
}

// Handle auth callback
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "default", "Handling callback")

		// Check for CSRF cookie
		c, err := r.Cookie(s.config.CSRFCookieName)
		if err != nil {
			logger.Warnf("Missing CSRF cookie: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate state
		valid, redirect, err := authentication.ValidateCSRFCookie(r, c)
		if !valid {
			logger.Warnf("Error validating CSRF cookie: %v", err)
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
			scope = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
		}

		oauth2Config := oauth2.Config{
			ClientID:     s.config.ClientId,
			ClientSecret: s.config.ClientSecret,
			RedirectURL:  s.authenticator.RedirectUri(r),
			Endpoint:     provider.Endpoint(),
			Scopes:       scope,
		}

		// Exchange code for token
		oauth2Token, err := oauth2Config.Exchange(s.config.OIDCContext, r.URL.Query().Get("code"))
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
		verifier := provider.Verifier(&oidc.Config{ClientID: s.config.ClientId})
		idToken, err := verifier.Verify(s.config.OIDCContext, rawIDToken)
		if err != nil {
			logger.Warnf("failed to verify token: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		// Extract custom claims
		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			logger.Warnf("failed to extract claims: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		// Generate cookies
		email, ok := claims["email"]
		if ok {
			// Generate cookies
			http.SetCookie(w, s.authenticator.MakeIDCookie(r, email.(string)))
			logger.WithFields(logrus.Fields{
				"user": claims["email"].(string),
			}).Infof("Generated auth cookie")
		} else {
			logger.Errorf("failed to get email claims session")
		}

		// If name in null, empty or whitespace, use email address for name
		name, ok := claims["name"]
		if !ok || (ok && strings.TrimSpace(name.(string)) == "") {
			name = email.(string)
		}

		http.SetCookie(w, s.authenticator.MakeNameCookie(r, name.(string)))
		logger.WithFields(logrus.Fields{
			"name": name.(string),
		}).Infof("Generated name cookie")

		// Mapping groups
		groups := []string{}
		gInterface, ok := claims[s.config.GroupsAttributeName].([]interface{})
		if ok {
			groups = make([]string, len(gInterface))
			for i, v := range gInterface {
				groups[i] = v.(string)
			}
		} else {
			logger.Errorf("failed to get groups claims session. GroupsAttributeName: %s", s.config.GroupsAttributeName)
		}

		logger.Printf("creating claims session with groups: %v", groups)
		if err := s.userinfo.Save(r, w, &v1alpha1.UserInfo{
			Username: name.(string),
			Email:    email.(string),
			Groups:   groups,
		}); err != nil {
			logger.Errorf("error saving session: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}
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
	err, nonce := authentication.Nonce()
	if err != nil {
		logger.Errorf("Error generating nonce, %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	http.SetCookie(w, s.authenticator.MakeCSRFCookie(r, nonce))
	logger.Debug("Set CSRF cookie and redirect to OIDC login")

	// Mapping scope
	var scope []string
	if s.config.Scope != "" {
		scope = []string{s.config.Scope}
	} else {
		scope = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
	}

	// clear existing claims session
	if err = s.userinfo.Clear(r, w); err != nil {
		logger.Errorf("error clearing session: %v", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     s.config.ClientId,
		ClientSecret: s.config.ClientSecret,
		RedirectURL:  s.authenticator.RedirectUri(r),
		Endpoint:     s.config.OIDCProvider.Endpoint(),
		Scopes:       scope,
	}

	state := fmt.Sprintf("%s:%s", nonce, authentication.ReturnUrl(r))

	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)

	return
}

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

func (s *Server) getGroupsFromSession(r *http.Request) ([]string, error) {
	userInfo, err := s.userinfo.Get(r)
	if err != nil {
		return nil, err
	}
	return userInfo.Groups, nil
}

func (s *Server) authzIsBypassed(r *http.Request) bool {
	for _, bypassURIPattern := range s.config.AuthZPassThrough {
		if authorization.PathMatches(r.URL.Path, bypassURIPattern) {
			s.log.Infof("authorization is disabled for %s", r.URL.Path)
			return true
		}
	}
	return false
}

// appends group prefix to groups
func (s *Server) getModifiedUserInfo(email string, groups []string) authorization.User {
	g := []string{"system:authenticated"}
	for _, group := range groups {
		g = append(g, fmt.Sprintf("%s%s", s.config.GroupClaimPrefix, group))
	}
	return authorization.User{
		Name:   email,
		Groups: g,
	}
}
