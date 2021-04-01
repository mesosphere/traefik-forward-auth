package rbac

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/mesosphere/traefik-forward-auth/internal/authorization"
	"github.com/mesosphere/traefik-forward-auth/internal/features"
)

const (
	allow = true
	deny  = false
)

type testCase struct {
	user   authorization.User
	verb   string
	url    *url.URL
	should bool
}

// makeURL makes url.URL object from relative path (e.g. /test) or full URL (e.g. http://domain.com/test)
func makeURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}

func getRBACAuthorizer(objs ...runtime.Object) *Authorizer {
	return NewAuthorizer(fake.NewSimpleClientset(objs...), nil)
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
	r, err := a.GetRolesBoundToUser(u1)

	assert.NoError(t, err)
	assert.Equal(t, len(r.Items), 2)

	// order of items in the returned array is actually not fixed so an iteration is required:

	hasr1Role := false
	for _, role := range r.Items {
		if role.Name == "r1" {
			hasr1Role = true
		}
	}
	assert.Equal(t, hasr1Role, true)

	hasAdminPathInRole := false
	for _, role := range r.Items {
		if role.Rules[0].NonResourceURLs[0] == "/admin" {
			hasAdminPathInRole = true
		}
	}
	assert.Equal(t, hasAdminPathInRole, true)

	u2 := authorization.User{Name: "u2", Groups: []string{"g1", "g2"}}

	r, err = a.GetRolesBoundToUser(u2)
	assert.NoError(t, err)
	assert.Equal(t, len(r.Items), 1)
	assert.Equal(t, r.Items[0].Name, "r3")
}

func TestRBACAuthorizer_Authorize(t *testing.T) {
	tests := []testCase{
		{authorization.User{Name: "u1"}, "get", makeURL("/"), allow},
		{authorization.User{Name: "u1"}, "post", makeURL("/"), deny},
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
		result, err := a.Authorize(test.user, test.verb, test.url)
		assert.NoError(t, err)
		assert.Equal(t, result, test.should)
	}
}

func TestRBACAuthorizer_Authorize2(t *testing.T) {
	test := testCase{
		user:   authorization.User{Name: "boyle@ldap.forumsys.com", Groups: []string{"oidc:chemists"}},
		url:    makeURL("/ops/portal/grafana/public/fonts/roboto/RxZJdnzeo3R5zSexge8UUVtXRa8TVwTICgirnJhmVJw.woff2"),
		should: allow,
	}

	role := makeRole("grafana-admin", []string{"*"}, []string{"/ops/portal/grafana", "/ops/portal/grafana/**"})
	rolebinding := makeBinding("User", "grafana-admin-boyle", "boyle@ldap.forumsys.com", "grafana-admin")

	a := getRBACAuthorizer(&role, &rolebinding)
	result, err := a.Authorize(test.user, test.verb, test.url)

	assert.NoError(t, err)
	assert.Equal(t, result, test.should)
}

func TestCaseInsensitiveSubjects(t *testing.T) {
	type testCase struct {
		authorizer authorization.Authorizer
		user       authorization.User
		url        string
		should     bool
	}

	// declare roles and bindings all lower-case
	role := makeRole("grafana-admin", []string{"*"}, []string{"/ops/portal/grafana", "/ops/portal/grafana/*"})
	rolebindings := makeClusterRoleBindingList(
		makeBinding("User", "grafana-admin-boyle", "boyle@ldap.forumsys.com", "grafana-admin"),
		makeBinding("Group", "grafana-admin-oidc-admins", "oidc:admins", "grafana-admin"),
	)

	// default authorizer
	defaultAuthorizer := getRBACAuthorizer(&role, rolebindings)

	// case-insensitive authorizer
	caseInsensitiveAuthorizer := getRBACAuthorizer(&role, rolebindings)
	caseInsensitiveAuthorizer.CaseInsensitiveSubjects = true

	tests := []testCase{
		// users
		{
			authorizer: defaultAuthorizer,
			user:       authorization.User{Name: "Boyle@ldap.forumsys.com", Groups: []string{"oidc:chemists"}},
			url:        "/ops/portal/grafana/rnJhmVJw.woff2",
			should:     false, // default case-sensitive user comparison shouldn't allow Boyle
		},
		{
			authorizer: caseInsensitiveAuthorizer,
			user:       authorization.User{Name: "Boyle@ldap.forumsys.com", Groups: []string{"oidc:chemists"}},
			url:        "/ops/portal/grafana/rnJhmVJw.woff2",
			should:     true, // case-insensitive user comparison should allow Boyle
		},
		// groups
		{
			authorizer: defaultAuthorizer,
			user:       authorization.User{Name: "agent47@ldap.forumsys.com", Groups: []string{"oidc:Admins"}},
			url:        "/ops/portal/grafana/rnJhmVJw.woff2",
			should:     false, // default case-sensitive group comparison shouldn't allow Admins group
		},
		{
			authorizer: caseInsensitiveAuthorizer,
			user:       authorization.User{Name: "agent47@ldap.forumsys.com", Groups: []string{"oidc:Admins"}},
			url:        "/ops/portal/grafana/rnJhmVJw.woff2",
			should:     true, // case-insensitive group comparison should allow Admins group
		},
	}

	for _, test := range tests {
		result, err := test.authorizer.Authorize(test.user, "GET", makeURL(test.url))
		assert.NoError(t, err)
		assert.Equal(t, result, test.should)
	}
}

func TestRBACAuthorizer_AuthorizePatternTypes(t *testing.T) {
	tests := []testCase{
		// user with "visitor" role only can GET root "/" path on any domain but cannot access any "/admin" or other URLs
		{authorization.User{Name: "u1"}, "get", makeURL("/"), allow},
		{authorization.User{Name: "u1"}, "get", makeURL("https://testdomain.com/"), allow},
		{authorization.User{Name: "u1"}, "post", makeURL("/admin"), deny},
		{authorization.User{Name: "u1"}, "post", makeURL("https://testdomain.com/admin"), deny},
		{authorization.User{Name: "u1"}, "post", makeURL("/reports"), deny},
		{authorization.User{Name: "u1"}, "post", makeURL("https://testdomain.com/reports"), deny},
		{authorization.User{Name: "u1"}, "post", makeURL("https://finance.com/finances"), deny},

		// user with "visitor" & "admin" roles can GET root "/" path on any domain and POST/ANY to "/admin" path on every domain
		{authorization.User{Name: "u2"}, "get", makeURL("/"), allow},
		{authorization.User{Name: "u2"}, "get", makeURL("https://testdomain.com/"), allow},
		{authorization.User{Name: "u2"}, "post", makeURL("/admin"), allow},
		{authorization.User{Name: "u2"}, "post", makeURL("https://testdomain.com/admin"), allow},
		{authorization.User{Name: "u2"}, "delete", makeURL("https://testdomain.com/admin"), allow},
		{authorization.User{Name: "u2"}, "delete", makeURL("https://testdomain.com/boss"), deny},

		// user with "visitor" & "testdomain-only-admin-poster" role can GET "/" path on any domain
		// but POST to "/admin" on testdomain.com only
		{authorization.User{Name: "u3"}, "get", makeURL("/"), allow},
		{authorization.User{Name: "u3"}, "get", makeURL("https://testdomain.com/"), allow},
		{authorization.User{Name: "u3"}, "post", makeURL("/admin"), deny},
		{authorization.User{Name: "u3"}, "post", makeURL("https://customdomain.com/admin"), deny},
		{authorization.User{Name: "u3"}, "post", makeURL("https://testdomain.com/admin"), allow},
		{authorization.User{Name: "u3"}, "delete", makeURL("https://testdomain.com/admin"), deny},

		// user with "wilddomain-only-admin-poster" role can only POST to "/admin" on URLs matching "*://*domain.com/admin"
		{authorization.User{Name: "u4"}, "post", makeURL("https://facebook.com/admin"), deny},
		{authorization.User{Name: "u4"}, "post", makeURL("https://customdomain.com/admin"), allow},
		{authorization.User{Name: "u4"}, "post", makeURL("https://testdomain.com/admin"), allow},
		{authorization.User{Name: "u4"}, "post", makeURL("https://testdomain.com/admin/res/theme.css"), deny}, // no * at the end
		{authorization.User{Name: "u4"}, "post", makeURL("http://customdomain.com/admin"), allow},             // same as https:// version
		{authorization.User{Name: "u4"}, "post", makeURL("http://testdomain.com/admin"), allow},               // same as https:// version
		{authorization.User{Name: "u4"}, "post", makeURL("https://testdomain.com/reports"), deny},

		// user with "https-regexpdomain-admin-poster" can post to anything under https://(first|second)domain/admin path
		{authorization.User{Name: "u5"}, "get", makeURL("https://firstdomain.com/"), deny},
		{authorization.User{Name: "u5"}, "get", makeURL("https://firstdomain.com/admin"), deny},
		{authorization.User{Name: "u5"}, "post", makeURL("https://firstdomain.com/admin"), allow},
		{authorization.User{Name: "u5"}, "post", makeURL("https://firstdomain.com/admin/users/create"), allow},
		{authorization.User{Name: "u5"}, "post", makeURL("https://seconddomain.com/admin/users/create"), allow},
	}

	roles := makeClusterRoleList(
		makeRole("visitor", []string{"get"}, []string{"/"}),
		makeRole("admin", []string{"*"}, []string{"/admin"}),
		makeRole("testdomain-only-admin-poster", []string{"post"}, []string{"https://testdomain.com/admin"}),
		makeRole("wilddomain-only-admin-poster", []string{"post"}, []string{"*://*domain.com/admin"}),
		makeRole("https-regexpdomain-admin-poster", []string{"post"}, []string{"~^https://(first|second)domain.com/admin"}),
	)

	bindings := makeClusterRoleBindingList(
		makeBinding("User", "u1b1", "u1", "visitor"),

		makeBinding("User", "u2b1", "u2", "visitor"),
		makeBinding("User", "u2b2", "u2", "admin"),

		makeBinding("User", "u3b1", "u3", "visitor"),
		makeBinding("User", "u3b2", "u3", "testdomain-only-admin-poster"),

		makeBinding("User", "u4b1", "u4", "wilddomain-only-admin-poster"),

		makeBinding("User", "u5b1", "u5", "https-regexpdomain-admin-poster"),
	)
	a := getRBACAuthorizer(roles, bindings)

	for _, test := range tests {
		result, err := a.Authorize(test.user, test.verb, test.url)
		assert.NoError(t, err)

		if !assert.Equal(t, result, test.should) {
			t.Logf("Authorize(%v, %v, %v) != %v", test.user, test.verb, test.url, test.should)
		}
	}
}

func init() {
	features.EnableV3URLPatternMatchin()
}
