package kubernetes

import (
	"fmt"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"os"
)

const (
	KubeConfigEnv = "KUBECONFIG"
)

// GetClientSet will attempt to get an external cluster configuration if the KUBECONFIG environment
// variable is set. Otherwise will attempt to get an in-cluster configuration.
func GetClientSet() (k8s.Interface, error) {
	configPath := os.Getenv(KubeConfigEnv)
	var config *rest.Config
	var err error
	if configPath != "" {
		config, err = clientcmd.BuildConfigFromFlags("", configPath)
		if err != nil {
			return nil, fmt.Errorf("error getting rest config from %s: %w", configPath, err)
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("error getting in cluster configuration: %w", err)
		}
	}

	clientset, err := k8s.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error getting clientset from config: %w", err)
	}
	return clientset, nil
}
