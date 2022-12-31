package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"
	api "github.com/turnly/oauth-middleware/internal/api"
	"github.com/turnly/oauth-middleware/internal/authentication"
	"github.com/turnly/oauth-middleware/internal/configuration"
	"github.com/turnly/oauth-middleware/internal/handlers"
	logger "github.com/turnly/oauth-middleware/internal/log"
	"github.com/turnly/oauth-middleware/internal/storage"
)

// Main
func main() {
	// Parse options
	config, err := configuration.NewConfig(os.Args[1:])
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	// Setup logger
	log := logger.NewDefaultLogger(config.LogLevel, config.LogFormat)

	// Perform config validation
	config.Validate()

	// Query the OIDC provider
	if err := config.LoadOIDCProviderConfiguration(); err != nil {
		log.Fatalln(err.Error())
	}

	authenticator := authentication.NewAuthenticator(config)
	var store api.StoreInterface

	// Prepare cookie session store (first key is for auth, the second one for encryption)
	hashKey := []byte(config.SecretString)
	blockKey := []byte(config.EncryptionKeyString)
	cookieStore := sessions.NewCookieStore(hashKey, blockKey)
	cookieStore.Options.MaxAge = int(config.Lifetime / time.Second)
	cookieStore.Options.HttpOnly = true
	cookieStore.Options.Secure = !config.InsecureCookie

	store = &storage.GorillaUserInfoStore{
		SessionStore: cookieStore,
		SessionName:  config.ClaimsSessionName,
		Auth:         authenticator,
	}

	// Build server
	server := handlers.NewServer(store, config)

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start server
	log.Debugf("Starting OAuth Middleware with the following configuration: %s", config)
	log.Info("Ahoy! The OAuth Middleware is now listening on port 4181")
	log.Info(http.ListenAndServe(":4181", nil))
}
