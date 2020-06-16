package handlers

import (
	"fmt"
	"github.com/mesosphere/traefik-forward-auth/internal/api/storage/v1alpha1"
	"net/http"
	"net/url"
	neturl "net/url"
	"strings"

	"github.com/containous/traefik/pkg/rules"
	"github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"k8s.io/client-go/kubernetes"

	"github.com/mesosphere/traefik-forward-auth/internal/authentication"
	"github.com/mesosphere/traefik-forward-auth/internal/authorization"
	"github.com/mesosphere/traefik-forward-auth/internal/authorization/rbac"
	"github.com/mesosphere/traefik-forward-auth/internal/configuration"
	internallog "github.com/mesosphere/traefik-forward-auth/internal/log"
)

const (
	impersonateUserHeader  = "Impersonate-User"
	impersonateGroupHeader = "Impersonate-Group"
)

// Server implements the HTTP server handling forwardauth
type Server struct {
	router        *rules.Router
	config        *configuration.Config
	authorizer    authorization.Authorizer
	authenticator *authentication.Authenticator
	userinfo      v1alpha1.UserInfoInterface
	log           logrus.FieldLogger
}

// NewServer creates a new forwardauth server
func NewServer(userinfo v1alpha1.UserInfoInterface, config *configuration.Config, clientset kubernetes.Interface) *Server {
	s := &Server{
		config:        config,
		log:           internallog.NewDefaultLogger(config.LogLevel, config.LogFormat),
		userinfo:      userinfo,
		authenticator: authentication.NewAuthenticator(config),
	}
	s.buildRoutes()
	if config.EnableRBAC {
		rbac := rbac.NewAuthorizer(clientset, s.log)
		rbac.CaseInsensitiveSubjects = config.CaseInsensitiveSubjects
		s.authorizer = rbac
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
	r.URL, _ = neturl.Parse(s.authenticator.GetRequestURI(r))

	if s.config.AuthHost == "" || len(s.config.CookieDomains) > 0 || r.Host == s.config.AuthHost {
		s.router.ServeHTTP(w, r)
	} else {
		// Redirect the client to the authHost.
		url := r.URL
		url.Scheme = r.Header.Get("X-Forwarded-Proto")
		url.Host = s.config.AuthHost
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
		c, err := r.Cookie(s.config.CookieName)
		if err != nil {
			s.notAuthenticated(logger, w, r)
			return
		}

		// Validate cookie
		sess, err := s.authenticator.ValidateSessionCookie(r, c)
		if err != nil {
			logger.Info(fmt.Sprintf("cookie validaton failure: %s", err.Error()))
			s.notAuthenticated(logger, w, r)
			return
		}

		// Validate user
		valid := s.authenticator.ValidateEmail(sess.EMail, s.config.Whitelist, s.config.Domains)
		if !valid {
			logger.WithFields(logrus.Fields{
				"email": sess.EMail,
			}).Errorf("invalid email")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Token forwarding requested now with no token stored in the session, reauth
		if s.config.ForwardTokenHeaderName != "" && sess.IDToken == "" {
			logger.Info("re-auth forced because token forwarding enabled and no token stored")
			s.notAuthenticated(logger, w, r)
			return
		}

		// Authorize user
		if s.config.EnableRBAC && !s.authzIsBypassed(r) {
			kubeUserInfo := s.makeKubeUserInfo(sess.EMail, sess.Groups)

			targetURL, err := url.Parse(s.authenticator.GetRequestURL(r))
			if err != nil {
				logger.Errorf("unable to parse target URL %s: %v", s.authenticator.GetRequestURL(r), err)
				http.Error(w, "Bad Gateway", 502)
				return
			}

			logger.Debugf("authorizing user: %s, groups: %s", kubeUserInfo.Name, kubeUserInfo.Groups)
			authorized, err := s.authorizer.Authorize(kubeUserInfo, r.Method, targetURL)
			if err != nil {
				logger.Errorf("error while authorizing %s: %v", kubeUserInfo, err)
				http.Error(w, "Bad Gateway", 502)
				return
			}

			if !authorized {
				logger.Infof("user %s is not authorized to `%s` in %s", kubeUserInfo.GetName(), r.Method, targetURL)
				//TODO:k3a: consider some kind of re-auth to recheck for new groups
				http.Error(w, "Not Authorized", 401)
				return
			}

			logger.Infof("user %s is authorized to `%s` in %s", kubeUserInfo.GetName(), r.Method, targetURL)
		}

		// Valid request
		logger.Debugf("Allow request from %s", sess.EMail)
		for _, headerName := range s.config.EmailHeaderNames {
			w.Header().Set(headerName, sess.EMail)
		}

		if s.config.EnableImpersonation {
			// Set impersonation headers
			logger.Debug(fmt.Sprintf("setting authorization token and impersonation headers: email: %s, groups: %s", sess.EMail, sess.Groups))
			w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", s.config.ServiceAccountToken))
			w.Header().Set(impersonateUserHeader, sess.EMail)
			w.Header().Set(impersonateGroupHeader, "system:authenticated")
			for _, group := range sess.Groups {
				w.Header().Add(impersonateGroupHeader, fmt.Sprintf("%s%s", s.config.GroupClaimPrefix, group))
			}
			w.Header().Set("Connection", cleanupConnectionHeader(w.Header().Get("Connection")))
		}

		if s.config.ForwardTokenHeaderName != "" {
			w.Header().Add(s.config.ForwardTokenHeaderName, s.config.ForwardTokenPrefix+sess.IDToken)
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

// AuthCallbackHandler handles the request as a callback from authentication provider.
// It validates CSRF, exchanges code-token for id-token and extracts groups from the id-token.
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "default", "Handling callback")

		// Check for CSRF cookie
		c, err := r.Cookie(s.config.CSRFCookieName)
		if err != nil {
			logger.Errorf("missing CSRF cookie: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate state
		valid, redirect, err := s.authenticator.ValidateCSRFCookie(r, c)
		if !valid {
			logger.Errorf("error validating CSRF cookie: %v", err)
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
			ClientID:     s.config.ClientID,
			ClientSecret: s.config.ClientSecret,
			RedirectURL:  s.authenticator.ComposeRedirectURI(r),
			Endpoint:     provider.Endpoint(),
			Scopes:       scope,
		}

		// Exchange code for token
		oauth2Token, err := oauth2Config.Exchange(s.config.OIDCContext, r.URL.Query().Get("code"))
		if err != nil {
			logger.Errorf("failed to exchange token: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			logger.Error("missing ID token")
			http.Error(w, "Bad Gateway", 502)
			return
		}

		var sess authentication.SessionCookie

		// Store the raw token if useful
		if s.config.ForwardTokenHeaderName != "" {
			sess.IDToken = rawIDToken
		}

		// Parse and verify ID Token payload.
		verifier := provider.Verifier(&oidc.Config{ClientID: s.config.ClientID})
		idToken, err := verifier.Verify(s.config.OIDCContext, rawIDToken)
		if err != nil {
			logger.Errorf("failed to verify token: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		// Extract custom claims
		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			logger.Errorf("failed to extract claims: %v", err)
			http.Error(w, "Bad Gateway", 502)
			return
		}

		email, ok := claims["email"]
		if ok {
			sess.EMail = email.(string)
		} else {
			logger.Warn("no email claim present in the ID token")
		}

		// If name in null, empty or whitespace, use email address for name
		name, ok := claims["name"]
		if !ok || (ok && strings.TrimSpace(name.(string)) == "") {
			name = email.(string)
		}

		http.SetCookie(w, s.authenticator.MakeNameCookie(r, name.(string)))
		logger.WithFields(logrus.Fields{
			"name": name.(string),
		}).Info("generated name cookie")

		// Mapping groups
		groups := []string{}
		groupsClaim, ok := claims[s.config.GroupsAttributeName].([]interface{})
		if ok {
			groups = make([]string, len(groupsClaim))
			for _, g := range groupsClaim {
				sess.Groups = append(sess.Groups, g.(string))
			}
		} else {
			logger.Warnf("failed to get groups claim from the ID token (GroupsAttributeName: %s)", s.config.GroupsAttributeName)
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
	nonce, err := s.authenticator.GenerateNonce()
	if err != nil {
		logger.Errorf("error generating nonce, %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	http.SetCookie(w, s.authenticator.MakeCSRFCookie(r, nonce))
	logger.Debug("sending CSRF cookie and a redirect to OIDC login")

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
		ClientID:     s.config.ClientID,
		ClientSecret: s.config.ClientSecret,
		RedirectURL:  s.authenticator.ComposeRedirectURI(r),
		Endpoint:     s.config.OIDCProvider.Endpoint(),
		Scopes:       scope,
	}

	state := fmt.Sprintf("%s:%s", nonce, s.authenticator.GetRequestURL(r))

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

// authzIsBypassed returns true if the request matches a bypass URI pattern
func (s *Server) authzIsBypassed(r *http.Request) bool {
	for _, bypassURIPattern := range s.config.AuthZPassThrough {
		if authorization.URLMatchesWildcardPattern(r.URL.Path, bypassURIPattern) {
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
		g = append(g, fmt.Sprintf("%s%s", s.config.GroupClaimPrefix, group))
	}
	return authorization.User{
		Name:   email,
		Groups: g,
	}
}