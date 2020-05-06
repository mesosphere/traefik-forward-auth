package tfa

import (
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"

	"github.com/containous/traefik/pkg/rules"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/mesosphere/traefik-forward-auth/internal/authorization/rbac"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"k8s.io/client-go/kubernetes"

	"github.com/mesosphere/traefik-forward-auth/internal/authorization"
	internallog "github.com/mesosphere/traefik-forward-auth/internal/log"
)

const (
	impersonateUserHeader  = "Impersonate-User"
	impersonateGroupHeader = "Impersonate-Group"
)

// Server implements the HTTP server handling forwardauth
type Server struct {
	router       *rules.Router
	sessionStore sessions.Store
	authorizer   authorization.Authorizer
	log          logrus.FieldLogger
}

// NewServer creates a new forwardauth server
func NewServer(sessionStore sessions.Store, clientset kubernetes.Interface) *Server {
	s := &Server{
		log: internallog.NewDefaultLogger(config.LogLevel, config.LogFormat),
	}
	s.buildRoutes()
	s.sessionStore = sessionStore
	if config.EnableRBAC {
		s.authorizer = rbac.NewAuthorizer(clientset, s.log)
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
	for name, rule := range config.Rules {
		var err error
		if rule.Action == "allow" {
			err = s.router.AddRoute(rule.formattedRule(), 1, s.AllowHandler(name))
		} else {
			err = s.router.AddRoute(rule.formattedRule(), 1, s.AuthHandler(name))
		}
		if err != nil {
			panic(fmt.Sprintf("could not add route: %v", err))
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

// RootHandler it the main handler (for / path)
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
	r.URL, _ = neturl.Parse(getRequestURIPath(r))

	if config.AuthHost == "" || len(config.CookieDomains) > 0 || r.Host == config.AuthHost {
		s.router.ServeHTTP(w, r)
	} else {
		// Redirect the client to the authHost.
		url := r.URL
		url.Scheme = r.Header.Get("X-Forwarded-Proto")
		url.Host = config.AuthHost
		logger.Debugf("redirect to %v", url.String())
		http.Redirect(w, r, url.String(), 307)
	}
}

// AllowHandler handles the request as implicite "allow", returining HTTP 200 response to the Traefik
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, rule, "Allow request")
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
		c, err := r.Cookie(config.CookieName)
		if err != nil {
			s.notAuthenticated(logger, w, r)
			return
		}

		// Validate cookie
		email, err := validateCookie(r, c)
		if err != nil {
			if err.Error() == "cookie has expired" {
				logger.Info("cookie has expired")
				s.notAuthenticated(logger, w, r)
			} else {
				logger.Errorf("invalid cookie: %v", err)
				http.Error(w, "Not authorized", 401)
			}
			return
		}

		// Validate user
		valid := validateEmail(email)
		if !valid {
			logger.WithFields(logrus.Fields{
				"email": email,
			}).Errorf("invalid email")
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

		if config.EnableRBAC && !s.authzIsBypassed(r) {
			kubeUserInfo := s.makeKubeUserInfo(email, groups)

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
		logger.Debugf("allow request from %s", email)
		for _, headerName := range config.EmailHeaderNames {
			w.Header().Set(headerName, email)
		}

		if config.EnableImpersonation {
			// Set impersonation headers
			logger.Debug(fmt.Sprintf("setting authorization token and impersonation headers: email: %s, groups: %s", email, groups))
			w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", config.ServiceAccountToken))
			w.Header().Set(impersonateUserHeader, email)
			w.Header().Set(impersonateGroupHeader, "system:authenticated")
			for _, group := range groups {
				w.Header().Add(impersonateGroupHeader, fmt.Sprintf("%s%s", config.GroupClaimPrefix, group))
			}
		}
		w.WriteHeader(200)
	}
}

// AuthCallbackHandler handles the request as a callback from authentication provider.
// It validates CSRF, exchanges code-token for id-token and extracts groups from the id-token.
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "default", "Handling callback")

		// Check for CSRF cookie
		c, err := r.Cookie(config.CSRFCookieName)
		if err != nil {
			logger.Warnf("missing CSRF cookie: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate state
		valid, redirect, err := validateCSRFCookie(r, c)
		if !valid {
			logger.Warnf("error validating CSRF cookie: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, clearCSRFCookie(r))

		provider := config.OIDCProvider

		// Mapping scope
		scope := []string{}
		if config.Scope != "" {
			scope = []string{config.Scope}
		} else {
			scope = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
		}

		oauth2Config := oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  composeRedirectURI(r),
			Endpoint:     provider.Endpoint(),
			Scopes:       scope,
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
		verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})
		idToken, err := verifier.Verify(config.OIDCContext, rawIDToken)
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
			http.SetCookie(w, makeIDCookie(r, email.(string)))
			logger.WithFields(logrus.Fields{
				"user": claims["email"].(string),
			}).Infof("generated auth cookie")
		} else {
			logger.Errorf("no email claim present in the ID token")
		}

		// If name in null, empty or whitespace, use email address for name
		name, ok := claims["name"]
		if !ok || (ok && strings.TrimSpace(name.(string)) == "") {
			name = email.(string)
		}

		http.SetCookie(w, makeNameCookie(r, name.(string)))
		logger.WithFields(logrus.Fields{
			"name": name.(string),
		}).Infof("generated name cookie")

		// Mapping groups
		groups := []string{}
		gInterface, ok := claims[config.GroupsAttributeName].([]interface{})
		if ok {
			groups = make([]string, len(gInterface))
			for i, v := range gInterface {
				groups[i] = v.(string)
			}
		} else {
			logger.Errorf("failed to get groups claim from the ID token (GroupsAttributeName: %s)", config.GroupsAttributeName)
		}

		logger.Printf("creating group claims session with groups: %v", groups)
		session, err := s.sessionStore.Get(r, config.GroupsSessionName)
		if err != nil {
			// from the .Get() documentation:
			// "It returns a new session and an error if the session exists but could not be decoded."
			// So it's ok to ignore and use the newly-created secure session! No need to hard-fail here.
			logger.Errorf("unable to decode existing session with group claims (creating a new one): %v", err)
		}

		if session == nil {
			// should never happen
			http.Error(w, "Bad Gateway", 502)
			return
		}

		session.Values["groups"] = make([]string, len(groups))
		copy(session.Values["groups"].([]string), groups)

		session.Options.Domain = cookieDomain(r)
		if err := session.Save(r, w); err != nil {
			logger.Errorf("error saving session: %v", err)
			http.Error(w, "Bad Gateway", 502)
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
			s.authRedirect(logger, w, r)
			return
		} else if strings.HasPrefix(format, "application/json") {
			bestFormat = "json"
		} else if strings.HasPrefix(format, "application/xml") {
			bestFormat = "xml"
		}
	}

	logger.Warnf("Non-HTML request: %v", acceptHeader)

	errStr := "Authentication expired. Reload page to re-authenticate."
	if bestFormat == "json" {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error": "`+errStr+`"}`, 401)
	} else if bestFormat == "xml" {
		w.Header().Set("Content-Type", "application/xml")
		http.Error(w, `<errors><error>`+errStr+`</error></errors>`, 401)
	} else {
		http.Error(w, errStr, 401)
	}
}

// authRedirect generates CSRF cookie and redirests to authentication provider to start the authentication flow.
func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) {
	// Error indicates no cookie, generate nonce
	nonce, err := generateNonce()
	if err != nil {
		logger.Errorf("error generating nonce, %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	http.SetCookie(w, makeCSRFCookie(r, nonce))
	logger.Debug("sending CSRF cookie and a redirect to OIDC login")

	// Mapping scope
	scope := []string{}
	if config.Scope != "" {
		scope = []string{config.Scope}
	} else {
		scope = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
	}

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  composeRedirectURI(r),
		Endpoint:     config.OIDCProvider.Endpoint(),
		Scopes:       scope,
	}

	state := fmt.Sprintf("%s:%s", nonce, getRequestURL(r))

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
	session, err := s.sessionStore.Get(r, config.GroupsSessionName)
	if err != nil {
		return nil, fmt.Errorf("error getting session: %w", err)
	}

	i, ok := session.Values["groups"]
	if !ok {
		return nil, nil
	}

	groups, ok := i.([]string)
	if !ok {
		return nil, fmt.Errorf("could not cast groups to string slice: %v", groups)
	}

	if groups == nil {
		return make([]string, 0), nil
	}
	return groups, nil
}

// authzIsBypassed returns true if the request matches a bypass URI pattern
func (s *Server) authzIsBypassed(r *http.Request) bool {
	for _, bypassURIPattern := range config.AuthZPassThrough {
		if authorization.PathMatches(r.URL.Path, bypassURIPattern) {
			s.log.Infof("authorization is disabled for %s", r.URL.Path)
			return true
		}
	}
	return false
}

// makeKubeUserInfo appends group prefix to all provided groups and adds "system:authenticated" group to the list
func (s *Server) makeKubeUserInfo(email string, groups []string) authorization.User {
	g := []string{"system:authenticated"}
	for _, group := range groups {
		g = append(g, fmt.Sprintf("%s%s", config.GroupClaimPrefix, group))
	}
	return authorization.User{
		Name:   email,
		Groups: g,
	}
}
