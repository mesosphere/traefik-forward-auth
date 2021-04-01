package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/mesosphere/traefik-forward-auth/internal/api/storage/v1alpha1"
	"github.com/mesosphere/traefik-forward-auth/internal/authentication"
	"github.com/mesosphere/traefik-forward-auth/internal/configuration"
	"github.com/mesosphere/traefik-forward-auth/internal/handlers"
	logger "github.com/mesosphere/traefik-forward-auth/internal/log"
	"github.com/mesosphere/traefik-forward-auth/internal/storage"
	"github.com/mesosphere/traefik-forward-auth/internal/storage/cluster"
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

	// Get clientset for Authorizers
	var clientset kubernetes.Interface
	if config.EnableRBAC {
		icc, err := rest.InClusterConfig()
		if err != nil {
			log.Fatalf("error getting in cluster configuration for RBAC client: %v", err)
		}
		clientset, err = kubernetes.NewForConfig(icc)
		if err != nil {
			log.Fatalf("error getting kubernetes client: %v", err)
		}
	}

	authenticator := authentication.NewAuthenticator(config)
	var userInfoStore v1alpha1.UserInfoInterface
	if !config.EnableInClusterStorage {
		// Prepare cookie session store (first key is for auth, the second one for encryption)
		cookieStore := sessions.NewCookieStore([]byte(config.SecretString), []byte(config.EncryptionKeyString))
		cookieStore.Options.MaxAge = int(config.Lifetime / time.Second)
		cookieStore.Options.HttpOnly = true
		cookieStore.Options.Secure = !config.InsecureCookie

		userInfoStore = &storage.GorillaUserInfoStore{
			SessionStore: cookieStore,
			SessionName:  config.ClaimsSessionName,
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
	server := handlers.NewServer(userInfoStore, config, clientset)

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.Debugf("starting with options: %s", config)
	log.Info("listening on :4181")
	log.Info(http.ListenAndServe(":4181", nil))
}
