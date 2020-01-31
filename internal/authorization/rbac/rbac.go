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
	// using config would be a circular import unless I wanted to fix everything now
	// TODO (jr): fix everything
	cacheSyncDuration = time.Minute * time.Duration(10)
)

type RBACAuthorizer struct {
	clientset                kubernetes.Interface
	clusterRoleLister        rbaclisterv1.ClusterRoleLister
	clusterRoleBindingLister rbaclisterv1.ClusterRoleBindingLister
	sharedInformerFactory    informers.SharedInformerFactory
	syncDuration             time.Duration
	informerStop             chan struct{}
	selector                 labels.Selector
}

func NewRBACAuthorizer(clientset kubernetes.Interface) *RBACAuthorizer {
	authz := &RBACAuthorizer{
		clientset:    clientset,
		syncDuration: cacheSyncDuration,
		selector:     labels.NewSelector(),
		informerStop: make(chan struct{}),
	}
	authz.prepareCache()
	return authz
}

// Private
func (ra *RBACAuthorizer) getRoleByName(name string) *rbacv1.ClusterRole {
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

func (ra *RBACAuthorizer) getRoleFromGroups(target, role string, groups []string) *rbacv1.ClusterRole {
	for _, group := range groups {
		if group == target {
			return ra.getRoleByName(role)
		}
	}
	return nil
}

func (ra *RBACAuthorizer) getRoleForSubject(user authorization.User, subject rbacv1.Subject, role string) *rbacv1.ClusterRole {
	if subject.Kind == "User" && subject.Name == user.GetName() {
		return ra.getRoleByName(role)
	} else if subject.Kind == "Group" {
		return ra.getRoleFromGroups(subject.Name, role, user.GetGroups())
	}
	return nil
}

func (ra *RBACAuthorizer) prepareCache() {
	ra.sharedInformerFactory = informers.NewSharedInformerFactory(ra.clientset, ra.syncDuration)
	ra.clusterRoleLister = ra.sharedInformerFactory.Rbac().V1().ClusterRoles().Lister()
	ra.clusterRoleBindingLister = ra.sharedInformerFactory.Rbac().V1().ClusterRoleBindings().Lister()
	ra.sharedInformerFactory.Start(ra.informerStop)
	ra.sharedInformerFactory.WaitForCacheSync(ra.informerStop)
}

// Public
func (ra *RBACAuthorizer) GetRoles(user authorization.User) (*rbacv1.ClusterRoleList, error) {
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
func (ra *RBACAuthorizer) Authorize(user authorization.User, requestVerb, requestResource string) (bool, error) {
	roles, err := ra.GetRoles(user)
	if err != nil {
		return false, err
	}

	if len(roles.Items) < 1 {
		return false, nil
	}

	for _, role := range roles.Items {
		for _, rule := range role.Rules {
			if VerbMatches(&rule, requestVerb) && NonResourceURLMatches(&rule, requestResource) {
				return true, nil
			}
		}
	}

	return false, nil
}

// Utility
func VerbMatches(rule *rbacv1.PolicyRule, requestedVerb string) bool {
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

func NonResourceURLMatches(rule *rbacv1.PolicyRule, requestedURL string) bool {
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
