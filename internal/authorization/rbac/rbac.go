package rbac

import (
	"log"
	"strings"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	rbaclisterv1 "k8s.io/client-go/listers/rbac/v1"

	"github.com/mesosphere/traefik-forward-auth/internal/authorization"
)

const (
	cacheSyncDuration = time.Minute * 10
)

// Authorizer implements the authorizer by watching and using ClusterRole and ClusterRoleBinding Kubernetes (RBAC) objects
type Authorizer struct {
	clientset                kubernetes.Interface
	clusterRoleLister        rbaclisterv1.ClusterRoleLister
	clusterRoleBindingLister rbaclisterv1.ClusterRoleBindingLister
	sharedInformerFactory    informers.SharedInformerFactory
	syncDuration             time.Duration
	informerStop             chan struct{}
	selector                 labels.Selector
}

// NewAuthorizer creates a new RBAC authorizer
func NewAuthorizer(clientset kubernetes.Interface) *Authorizer {
	authz := &Authorizer{
		clientset:    clientset,
		syncDuration: cacheSyncDuration,
		selector:     labels.NewSelector(),
		informerStop: make(chan struct{}),
	}
	authz.prepareCache()
	return authz
}

// Private

// getRoleByName finds the ClusterRole by its name or returns nil
func (ra *Authorizer) getRoleByName(name string) *rbacv1.ClusterRole {
	clusterRole, err := ra.clusterRoleLister.Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			// TFA's "internal" package doesn't make sense for expanding functionality.
			// IMO, TFA should be rewritten completely using current golang design standards
			// TODO(jr): Rewrite TFA as a lightweight forward proxy
			// ^^ using stdlib log because I don't want to parse the configuration file again for
			// two log messages... (jr) (or muck up my interfaces by passing in a log object..)
			log.Printf("role binding %s is bound to non-existent role", name)
		} else {
			log.Printf("error getting role bound to %s: %v", name, err)
		}
		return nil
	}
	return clusterRole
}

// getRoleFromGroups returns role specified in roleNameRef only if subjectGroupName is in the userGroups list
func (ra *Authorizer) getRoleFromGroups(roleNameRef, subjectGroupName string, userGroups []string) *rbacv1.ClusterRole {
	// for every user group...
	for _, group := range userGroups {
		// if the group matches the group name in the subject, return the role
		if group == subjectGroupName {
			return ra.getRoleByName(roleNameRef)
		}
	}

	// no user group match this subjectGroupName
	return nil
}

// getRoleForSubject gets the role bound to the subject depending on the subject kind (user or group).
// Returns nil if there is no rule matching or an unknown subject Kind is provided
func (ra *Authorizer) getRoleForSubject(user authorization.User, subject rbacv1.Subject, roleNameRef string) *rbacv1.ClusterRole {
	if subject.Kind == "User" && subject.Name == user.GetName() {
		return ra.getRoleByName(roleNameRef)
	} else if subject.Kind == "Group" {
		return ra.getRoleFromGroups(roleNameRef, subject.Name, user.GetGroups())
	}
	return nil
}

func (ra *Authorizer) prepareCache() {
	ra.sharedInformerFactory = informers.NewSharedInformerFactory(ra.clientset, ra.syncDuration)
	ra.clusterRoleLister = ra.sharedInformerFactory.Rbac().V1().ClusterRoles().Lister()
	ra.clusterRoleBindingLister = ra.sharedInformerFactory.Rbac().V1().ClusterRoleBindings().Lister()
	ra.sharedInformerFactory.Start(ra.informerStop)
	ra.sharedInformerFactory.WaitForCacheSync(ra.informerStop)
}

// Public

// GetRolesBoundToUser returns list of roles bound to the specified user or groups the user is part of
func (ra *Authorizer) GetRolesBoundToUser(user authorization.User) (*rbacv1.ClusterRoleList, error) {
	clusterRoles := rbacv1.ClusterRoleList{}
	clusterRoleBindings, err := ra.clusterRoleBindingLister.List(ra.selector)
	if err != nil {
		return nil, err
	}
	for _, clusterRoleBinding := range clusterRoleBindings {
		for _, subject := range clusterRoleBinding.Subjects {
			role := ra.getRoleForSubject(user, subject, clusterRoleBinding.RoleRef.Name)
			if role != nil {
				clusterRoles.Items = append(clusterRoles.Items, *role)
				break
			}
		}
	}
	return &clusterRoles, nil
}

// Interface methods

// Authorize performs the authorization logic
func (ra *Authorizer) Authorize(user authorization.User, requestVerb, requestResource string) (bool, error) {
	roles, err := ra.GetRolesBoundToUser(user)
	if err != nil {
		return false, err
	}

	// deny if no roles defined
	if len(roles.Items) < 1 {
		return false, nil
	}

	// check all rules in the list of roles to see if any matches
	for _, role := range roles.Items {
		for _, rule := range role.Rules {
			if verbMatches(&rule, requestVerb) && nonResourceURLMatches(&rule, requestResource) {
				return true, nil
			}
		}
	}

	// no rules match the request -> deny
	return false, nil
}

// Utility

// verbMatches returns true if the requested verb matches a verb specifid in the rule
// Also matches if the rule mentiones special "all verbs" rule *
func verbMatches(rule *rbacv1.PolicyRule, requestedVerb string) bool {
	for _, ruleVerb := range rule.Verbs {
		if ruleVerb == rbacv1.VerbAll {
			return true
		}
		if strings.ToLower(ruleVerb) == strings.ToLower(requestedVerb) {
			return true
		}
	}

	return false
}

// nonResourceURLMatches returns true if the requested URL matches a policy the rule
func nonResourceURLMatches(rule *rbacv1.PolicyRule, requestedURL string) bool {
	for _, ruleURL := range rule.NonResourceURLs {
		if ruleURL == rbacv1.NonResourceAll {
			return true
		}
		if authorization.PathMatches(requestedURL, ruleURL) {
			return true
		}
	}
	return false
}
