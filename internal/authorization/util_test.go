package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathMatches(t *testing.T) {
	type test struct {
		url     string
		pattern string
		allow   bool
	}

	var testCases = []test{
		{url: "/", pattern: "/", allow: true},
		{url: "/xyz/subpath1/subpath2", pattern: "/xyz/*/subpath3", allow: false},
		{url: "/ops/portal/admin", pattern: "/ops/portal/", allow: false},
		{url: "/ops/portal/xyz.png", pattern: "/ops/portal/*.png", allow: false},
		{url: "/ops/portal/kibana/app/kibana", pattern: "/ops/portal/kibana/*", allow: true},
	}

	for _, c := range testCases {
		assert.Equal(t, c.allow, PathMatches(c.url, c.pattern))
	}
}
