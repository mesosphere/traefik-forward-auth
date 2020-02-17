package groupmemberof

import (
	"testing"

	"gotest.tools/assert"
)

type testCase struct {
	userGroups     []string
	groupsMemberOf string
	should         bool
}

func TestGroupMemberOfAuthorizer_Authorize(t *testing.T) {

	groupsMemberOf := "admin user"

	userGroups1 := []string{"admin", "user", "group"}
	userGroups2 := []string{"admin1", "user1"}

	tests := []testCase{
		testCase{userGroups: userGroups1, groupsMemberOf: groupsMemberOf, should: true},
		testCase{userGroups: userGroups2, groupsMemberOf: groupsMemberOf, should: false},
	}

	for _, test := range tests {
		m := map[string]interface{}{
			"userGroups":     test.userGroups,
			"groupsMemberOf": test.groupsMemberOf,
		}

		result, _ := Authorize(m)
		assert.Equal(t, result, test.should)
	}
}
