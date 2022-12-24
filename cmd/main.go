package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"
	k8s "k8s.io/client-go/kubernetes"

	"github.com/turnly/oauth-middleware/internal/api/storage/v1alpha1"
	"github.com/turnly/oauth-middleware/internal/authentication"
	"github.com/turnly/oauth-middleware/internal/configuration"
	"github.com/turnly/oauth-middleware/internal/handlers"
	kubernetes "github.com/turnly/oauth-middleware/internal/kubernetes"
	logger "github.com/turnly/oauth-middleware/internal/log"
	"github.com/turnly/oauth-middleware/internal/storage"
	"github.com/turnly/oauth-middleware/internal/storage/cluster"
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
	// Get clientset for Authorizers
	var clientset k8s.Interface
	if config.EnableRBAC || config.EnableInClusterStorage {
		var err error
		clientset, err = kubernetes.GetClientSet()
		if err != nil {
			log.Fatalf("error getting kubernetes client: %v", err)
		}
	}

	var userInfoStore v1alpha1.UserInfoInterface
	if !config.EnableInClusterStorage {
		// Prepare cookie session store (first key is for auth, the second one for encryption)
		hashKey := []byte(config.SecretString)
		blockKey := []byte(config.EncryptionKeyString)
		cookieStore := sessions.NewCookieStore(hashKey, blockKey)
		cookieStore.Options.MaxAge = int(config.Lifetime / time.Second)
		cookieStore.Options.HttpOnly = true
		cookieStore.Options.Secure = !config.InsecureCookie

		userInfoStore = &storage.GorillaUserInfoStore{
			SessionStore: cookieStore,
			SessionName:  config.ClaimsSessionName,
			Auth:         authenticator,
		}
	} else {
		userInfoStore = cluster.NewClusterStore(
			clientset,
			config.ClusterStoreNamespace,
			config.SecretString,
			config.Lifetime,
			time.Duration(config.ClusterStoreCacheTTL)*time.Second,
			authenticator)

		gc := cluster.NewGC(userInfoStore.(*cluster.ClusterStorage), time.Minute, false, true)

		if err := gc.Start(); err != nil {
			log.Fatalf("error starting GC process: %v", err)
		}
	}
	// Build server
	server := handlers.NewServer(userInfoStore, clientset, config)

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.Debugf("starting with options: %s", config)
	log.Info("listening on :4181")
	log.Info(http.ListenAndServe(":4181", nil))
}
