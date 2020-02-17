package rbac

import (
	"testing"

	"gotest.tools/assert"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/mesosphere/traefik-forward-auth/internal/authorization"
)

const (
	allow = true
	deny  = false
)

type testCase struct {
	user   authorization.User
	verb   string
	url    string
	should bool
}

func getRBACAuthorizer(objs ...runtime.Object) *RBACAuthorizer {
	return NewRBACAuthorizer(fake.NewSimpleClientset(objs...))
}

func makeRole(name string, verbs, urls []string) rbacv1.ClusterRole {
	return rbacv1.ClusterRole{
		TypeMeta: v1.TypeMeta{
			Kind: "ClusterRole",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: name,
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:           verbs,
				NonResourceURLs: urls,
			},
		},
	}
}

func makeBinding(kind, name, subject, role string) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		TypeMeta: v1.TypeMeta{
			Kind: "ClusterRole",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: kind,
				Name: subject,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: role,
		},
	}
}

func makeClusterRoleList(roles ...rbacv1.ClusterRole) *rbacv1.ClusterRoleList {
	return &rbacv1.ClusterRoleList{
		TypeMeta: v1.TypeMeta{Kind: "ClusterRoleList"},
		ListMeta: v1.ListMeta{},
		Items:    roles,
	}
}

func makeClusterRoleBindingList(bindings ...rbacv1.ClusterRoleBinding) *rbacv1.ClusterRoleBindingList {
	return &rbacv1.ClusterRoleBindingList{
		TypeMeta: v1.TypeMeta{Kind: "ClusterRoleBindingList"},
		ListMeta: v1.ListMeta{},
		Items:    bindings,
	}
}

func TestRBACAuthorizer_GetRoles(t *testing.T) {
	roles := makeClusterRoleList(
		makeRole("r1", []string{"get"}, []string{"/"}),
		makeRole("r2", []string{"*"}, []string{"/admin"}),
		makeRole("r3", []string{"*"}, []string{"/foo/bar/*"}),
	)

	bindings := makeClusterRoleBindingList(
		makeBinding("User", "b1", "u1", "r1"),
		makeBinding("User", "b2", "u1", "r2"),
		makeBinding("Group", "b3", "g1", "r3"),
	)

	a := getRBACAuthorizer(roles, bindings)

	u1 := authorization.User{Name: "u1"}
	r, err := a.GetRoles(u1)

	assert.NilError(t, err)
	assert.Equal(t, len(r.Items), 2)
	assert.Equal(t, r.Items[0].Name, "r1")
	assert.Equal(t, r.Items[1].Rules[0].NonResourceURLs[0], "/admin")

	u2 := authorization.User{Name: "u2", Groups: []string{"g1", "g2"}}

	r, err = a.GetRoles(u2)
	assert.NilError(t, err)
	assert.Equal(t, len(r.Items), 1)
	assert.Equal(t, r.Items[0].Name, "r3")
}

func TestRBACAuthorizer_Authorize(t *testing.T) {
	tests := []testCase{
		{authorization.User{Name: "u1"}, "get", "/", allow},
		{authorization.User{Name: "u1"}, "post", "/", deny},
	}

	roles := makeClusterRoleList(
		makeRole("r1", []string{"get"}, []string{"/"}),
		makeRole("r2", []string{"*"}, []string{"/admin"}),
		makeRole("r3", []string{"*"}, []string{"/foo/bar/*"}),
	)

	bindings := makeClusterRoleBindingList(
		makeBinding("User", "b1", "u1", "r1"),
		makeBinding("User", "b2", "u1", "r2"),
		makeBinding("Group", "b3", "g1", "r3"),
	)
	a := getRBACAuthorizer(roles, bindings)

	for _, test := range tests {
		m := map[string]interface{}{
			"user":            test.user,
			"requestVerb":     test.verb,
			"requestResource": test.url,
		}
		result, err := a.Authorize(m)
		assert.NilError(t, err)
		assert.Equal(t, result, test.should)
	}
}
