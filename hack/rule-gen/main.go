// CLI for generating rules for various endpoints

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

type RoleGroups struct {
	Name      string     `yaml:"name"`
	Endpoints []Endpoint `yaml:"endpoints"`
}

type Endpoint struct {
	Name  string   `yaml:"name"`
	Paths []string `yaml:"paths"`
}

type MetaDataTemplate struct {
	Name string `yaml:"name"`
}

type RulesTemplate struct {
	NonResourceURLs []string `yaml:"nonResourceURLs"`
	Verbs           []string `yaml:"verbs"`
}

type ClusterRoleTemplate struct {
	APIVersion string           `yaml:"apiVersion"`
	Kind       string           `yaml:"kind"`
	Metadata   MetaDataTemplate `yaml:"metadata"`
	Rules      []RulesTemplate  `yaml:"rules"`
}

var defaultVerbMap = map[string][]string{
	"view":  {"get", "head"},
	"edit":  {"get", "head", "post", "put"},
	"admin": {"get", "head", "post", "put", "delete"},
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("usage: %s <config>\n", os.Args[0])
		os.Exit(1)
	}

	c, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("could not read: %s\n", os.Args[1])
		os.Exit(1)
	}

	rg := RoleGroups{}
	if err := yaml.Unmarshal(c, &rg); err != nil {
		fmt.Printf("error parsing %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}

	var roles []ClusterRoleTemplate
	for _, endpoint := range rg.Endpoints {
		groupName := rg.Name
		name := endpoint.Name
		paths := endpoint.Paths

		for action, verbs := range defaultVerbMap {
			roles = append(roles, makeRole(
				groupName,
				name,
				action,
				paths,
				verbs,
			))
		}
	}

	for _, role := range roles {
		b, err := yaml.Marshal(&role)
		if err != nil {
			panic(err.Error())
		}
		fmt.Printf("---\n%s\n", b)
	}
}

func makeRole(groupName, name, action string, paths, verbs []string) ClusterRoleTemplate {
	roleName := fmt.Sprintf("%s-%s-%s", groupName, name, action)
	cr := ClusterRoleTemplate{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "ClusterRole",
		Metadata: MetaDataTemplate{
			Name: roleName,
		},
		Rules: []RulesTemplate{
			{
				NonResourceURLs: paths,
				Verbs:           verbs,
			},
		},
	}
	return cr
}
