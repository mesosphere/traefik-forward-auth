package authorization

import (
	"strings"
)

func PathMatches(url, pattern string) bool {
	return pattern == url ||
		(strings.HasSuffix(pattern, "*") && strings.HasPrefix(url, strings.TrimRight(pattern, "*")))
}
