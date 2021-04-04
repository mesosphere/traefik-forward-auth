package main

import (
	"github.com/mesosphere/traefik-forward-auth/internal/api/storage/v1alpha1"
	kubernetes "github.com/mesosphere/traefik-forward-auth/internal/kubernetes"
	"github.com/mesosphere/traefik-forward-auth/internal/storage"
	"github.com/mesosphere/traefik-forward-auth/internal/storage/cluster"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"
	internal "github.com/mesosphere/traefik-forward-auth/internal"
	logger "github.com/mesosphere/traefik-forward-auth/internal/log"
	k8s "k8s.io/client-go/kubernetes"
)

// Main
func main() {
	// Parse options
	config := internal.NewGlobalConfig(os.Args[1:])

	// Setup logger
	log := logger.NewDefaultLogger(config.LogLevel, config.LogFormat)

	// Perform config validation
	config.Validate()

	// Query the OIDC provider
	config.SetOidcProvider()

	// Get clientset for Authorizers
	var clientset k8s.Interface
	if config.EnableRBAC || config.EnableInClusterStorage {
		var err error
		clientset, err = kubernetes.GetClientSet()
		if err != nil {
			log.Fatalf("error getting kubernetes client: %v", err)
		}
	} else {
		clientset = nil
	}

	var userInfoStore v1alpha1.UserInfoInterface
	if !config.EnableInClusterStorage {
		// Prepare cookie session store (first key is for auth, the second one for encryption)
		cookieStore := sessions.NewCookieStore(config.Secret, []byte(config.SessionKey))
		cookieStore.Options.MaxAge = int(config.Lifetime / time.Second)
		cookieStore.Options.HttpOnly = true
		cookieStore.Options.Secure = !config.InsecureCookie

		userInfoStore = &storage.GorillaUserInfoStore{
			SessionStore: cookieStore,
			SessionName:  config.ClaimsSessionName,
		}
	} else {
		clusterStorage := cluster.NewClusterStore(
			clientset,
			config.ClusterStoreNamespace,
			string(config.Secret),
			config.Lifetime,
			time.Duration(config.ClusterStoreCacheTTL)*time.Second)

		gc := cluster.NewGC(clusterStorage, time.Minute, false, true)

		if err := gc.Start(); err != nil {
			log.Fatalf("error starting GC process: %v", err)
		}
	}
	// Build server
	server := internal.NewServer(userInfoStore, clientset)

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.Debugf("Starting with options: %s", config)
	log.Info("Listening on :4181")
	log.Info(http.ListenAndServe(":4181", nil))
}
