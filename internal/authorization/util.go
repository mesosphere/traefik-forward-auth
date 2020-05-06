package authorization

import (
	"strings"
)

// PathMatches returns true if the URL matches the pattern containing an optional wildcard '*' character
func PathMatches(url, pattern string) bool {
	return pattern == url ||
		(strings.HasSuffix(pattern, "*") && strings.HasPrefix(url, strings.TrimRight(pattern, "*")))
}
