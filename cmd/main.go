package main

import (
	"fmt"
	"net/http"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	internal "github.com/mesosphere/traefik-forward-auth/internal"
	logger "github.com/mesosphere/traefik-forward-auth/internal/log"
)

// Main
func main() {
	// Parse options
	config, err := internal.NewConfig(nil)
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

	// Build server
	server := internal.NewServer(config, clientset)

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.Debugf("starting with options: %s", config)
	log.Info("listening on :4181")
	log.Info(http.ListenAndServe(":4181", nil))
}
