// This is a partial attempt at improving authorization performance by indexing roles by subject.
// With the use of informer handlers, these indexes would be kept up to date.. with periodic resyncing
// There are some edge cases that need to be covered, but once implemented would reduce the complexity of
// authorization from O(n^2) to O(1)
package graveyard

import (
	"sync"

	rbacv1 "k8s.io/api/rbac/v1"
)

type SubjectIndex map[string][]*rbacv1.ClusterRole

type RoleWithSubjects struct {
	Role     *rbacv1.ClusterRole
	Subjects []rbacv1.Subject
}

type RoleSubjectIndex struct {
	// UserIndex maps subjects of kind User to policy rules
	UserIndex SubjectIndex

	// GroupIndex maps subject of kind Group to policy rules
	GroupIndex SubjectIndex

	// RolesIndex maps Role name to a pointer to the Role object
	RolesIndex map[string]*rbacv1.ClusterRole

	mux sync.Mutex
}

func New(roles *rbacv1.ClusterRoleList, bindings *rbacv1.ClusterRoleBindingList) *RoleSubjectIndex {
	rsidx := &RoleSubjectIndex{}
	build(rsidx, roles, bindings)
	return rsidx
}

func (r *RoleSubjectIndex) ReSync(roles *rbacv1.ClusterRoleList, bindings *rbacv1.ClusterRoleBindingList) {
	r.mux.Lock()
	defer r.mux.Unlock()
	build(r, roles, bindings)
}

func (r *RoleSubjectIndex) UpdateRoleIndex(role *rbacv1.ClusterRole) {
	r.mux.Lock()
	defer r.mux.Unlock()

	old, ok := r.RolesIndex[role.Name]
	if !ok {
		if hasNonResourceRules(role) {
			r.RolesIndex[role.Name] = role.DeepCopy()
		}
		return
	}

	if !hasNonResourceRules(role) {
		r.deleteRole(role.Name)
		return
	}

	// preserves pointer address???
	role.DeepCopyInto(old)
}

func (r *RoleSubjectIndex) deleteRole(name string) {
	// clean up references
	removeReferences(name, r.UserIndex)
	removeReferences(name, r.GroupIndex)

	// Delete the key
	delete(r.RolesIndex, name)
}

func (r *RoleSubjectIndex) DeleteRole(name string) {
	r.mux.Lock()
	defer r.mux.Unlock()
	r.deleteRole(name)
}

func (r *RoleSubjectIndex) getSubjectIndex(kind string) SubjectIndex {
	switch kind {
	case "User":
		return r.UserIndex
	case "Group":
		return r.GroupIndex
	default:
		return r.UserIndex
	}
}

func removeReferences(name string, index SubjectIndex) {
	match := false
	dirty := make([]string, 0)
	for k, v := range index {
		n := make([]*rbacv1.ClusterRole, len(v))
		for _, role := range v {
			if role.Name == name {
				match = true
				continue
			}
			n = append(n, role)
		}
		if match {
			if len(n) == 0 {
				dirty = append(dirty, k)
				continue
			}
			index[k] = n
		}
	}
	// Delete any empty index
	for _, name := range dirty {
		delete(index, name)
	}
}

func hasNonResourceRules(role *rbacv1.ClusterRole) bool {
	for _, rule := range role.Rules {
		if len(rule.NonResourceURLs) > 0 {
			return true
		}
	}
	return false
}

func build(rsidx *RoleSubjectIndex, roles *rbacv1.ClusterRoleList, bindings *rbacv1.ClusterRoleBindingList) {
	rsidx.UserIndex = make(SubjectIndex)
	rsidx.GroupIndex = make(SubjectIndex)
	rsidx.RolesIndex = make(map[string]*rbacv1.ClusterRole)

	for _, role := range roles.Items {
		// only index roles containing at least one nonResourceURLs
		if hasNonResourceRules(&role) {
			rsidx.RolesIndex[role.Name] = role.DeepCopy()
		}
	}

	for _, binding := range bindings.Items {
		role, ok := rsidx.RolesIndex[binding.RoleRef.Name]
		if !ok {
			continue
		}

		for _, subject := range binding.Subjects {
			idx := rsidx.getSubjectIndex(subject.Kind)
			for _, rule := range role.Rules {
				if len(rule.NonResourceURLs) > 0 {
					idx[subject.Name] = append(idx[subject.Name], role)
				}
			}
		}
	}
}
