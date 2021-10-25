package authorization

import (
	"errors"
	"regexp"
	"strings"
	"sync"

	"github.com/mesosphere/traefik-forward-auth/internal/features"
)

var (
	globalRECache  = newRegexpCache()
	invalidExpr    = &regexp.Regexp{}
	errInvalidExpr = errors.New("invalid regular expression")
)

type regexpCache struct {
	mu    sync.RWMutex
	cache map[string]*regexp.Regexp
}

func newRegexpCache() *regexpCache {
	return &regexpCache{
		cache: make(map[string]*regexp.Regexp),
	}
}

// get returns regexp cached under "expr" key or nil if not cached
func (rc *regexpCache) get(expr string) *regexp.Regexp {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	re, _ := rc.cache[expr]
	return re
}

// wildcardPatternToRegexp converts pattern containing optional * characters
// to a regular expression string. A special care is taken to quote
// any regular expression characters in the input pattern first.
func (rc *regexpCache) wildcardPatternToRegexp(pattern string) string {
	// quote all regexp metacharacters to make the safe expression which would match
	// the input as being a literal string (basically a regexp for string equality test)
	pattern = regexp.QuoteMeta(pattern)
	// replace two ** input characters (now quoted by '\') with an expression to match anything
	pattern = strings.ReplaceAll(pattern, `\*\*`, `.*`)
	// replace the remaining single escaped '*' with an expression to match continous stream
	// (by using non-greedy ? specifier) of characters not containing any slash (path separator)
	pattern = strings.ReplaceAll(pattern, `\*`, `[^/]*?`)
	// request pattern to match the subject fully by adding beginning and ending anchors
	return `^` + pattern + `$`
}

// GetOrCompile attempts to get compiled regexp from the cache or attempts to compile it and cache.
// If the expr is not a valid expression, the function forwards the error from regexp.Compile
// If asWildcard is true, the expression will be interpreted as a wildcard pattern
func (rc *regexpCache) GetOrCompile(expr string, asWildcard bool) (*regexp.Regexp, error) {
	var err error

	// attempt to get already-compiled regexp from cache first
	re := rc.get(expr)
	if re != nil {
		if re == invalidExpr {
			// if invalid expression is cached, return early with an error
			return nil, errInvalidExpr
		}
		return re, nil // return cached Regexp object
	}

	if strings.TrimSpace(expr) == "" {
		// mark empty expr as failed compilation for extra safety
		err = errInvalidExpr
		re = nil
	} else {
		// attempt to compile a new regexp
		exprToCompile := expr
		if asWildcard {
			// if wildcard mode requested, convert first
			exprToCompile = rc.wildcardPatternToRegexp(expr)
		}
		re, err = regexp.Compile(exprToCompile)
	}

	// cache failed regexpes as invalid to prevent their re-compilation
	if err != nil {
		re = invalidExpr
	}

	// store in the cache under the input "expr" as the key
	rc.mu.Lock()
	rc.cache[expr] = re
	rc.mu.Unlock()

	return re, err
}

// MatchString returns true if subject matches the expression expr.
// The expr parameter can be a regular expression string or wildcard pattern (if asWildcard is true).
// Wildcard pattern may not contain any '*' character in which case a direct string comparison is performed.
func (rc *regexpCache) MatchString(subject string, expr string, asWildcard bool) bool {
	// Attempt to speed up asWildcard=true patterns by doing quick direct literal comparison first.
	// Wildcard patterns always match themselves ("x*x", "x*x", true) = true and the speed tests
	// suggest s negative result of this comparison do not make significant difference in total speed
	if asWildcard && expr == subject {
		return true
	}

	re, err := rc.GetOrCompile(expr, asWildcard)
	if err != nil {
		return false
	}

	return re.MatchString(subject)
}

// URLMatchesRegexp returns true if the URL matches the regular expresson
func URLMatchesRegexp(url, regex string) bool {
	return globalRECache.MatchString(url, regex, false)
}

// URLMatchesWildcardPattern returns true if the URL matches the pattern containing optional wildcard '*' characters
func URLMatchesWildcardPattern(url, pattern string) bool {
	if features.V3URLPatternMatchingEnabled() {
		return globalRECache.MatchString(url, pattern, true)
	} else {
		return pattern == url || (strings.HasSuffix(pattern, "*") && strings.HasPrefix(url, strings.TrimRight(pattern, "*")))
	}
}
