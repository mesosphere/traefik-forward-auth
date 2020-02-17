package groupmemberof

import (
	"strings"

	"github.com/go-playground/validator/v10"
)

// Authorize function interface methods
func Authorize(m map[string]interface{}) (bool, error) {

	validate := validator.New()

	split := m["groupsMemberOf"].(string)
	groupsMemberOf := strings.Split(split, " ")
	errs := validate.Var(groupsMemberOf, "omitempty,required,min=1")
	if errs != nil {
		return false, errs
	}

	userGroups := m["userGroups"].([]string)
	errs = validate.Var(userGroups, "omitempty,required,min=1")
	if errs != nil {
		return false, errs
	}

	found := Find(userGroups, groupsMemberOf)
	if found {
		return true, nil
	}

	return false, nil
}

// Find function utility
func Find(groupsOIDC []string, groupsMemberOf []string) bool {

	for _, oidc := range groupsOIDC {
		for _, memberof := range groupsMemberOf {
			if oidc == memberof {
				return true
			}
		}
	}
	return false
}
