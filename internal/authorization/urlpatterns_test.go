package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mesosphere/traefik-forward-auth/internal/features"
)

func TestWildcardMatches(t *testing.T) {
	type test struct {
		pattern string
		url     string
		matches bool
	}

	var testCases = []test{
		{pattern: "", url: "", matches: true},
		{pattern: "", url: "/", matches: false},
		{pattern: "/", url: "", matches: false},
		{pattern: "/", url: "/", matches: true},
		{pattern: "/xyz/*/subpath3", url: "/xyz/subpath1/subpath2", matches: false},
		{pattern: "/ops/portal/", url: "/ops/portal/admin", matches: false},
		{pattern: "/ops/portal/*.png", url: "/ops/portal/xyz.png", matches: true},
		{pattern: "/ops/portal/*.png", url: "/ops/portal/res/xyz.png", matches: false},
		{pattern: "/ops/portal/**/*.png", url: "/ops/portal/res/xyz.png", matches: true},
		{pattern: "/ops/portal/kibana", url: "/ops/portal/kibana/app/kibana", matches: false},
		{pattern: "/ops/portal/kibana/**", url: "/ops/portal/kibana/app/kibana", matches: true},
		{pattern: "/ops/portal/grafana/**", url: "/ops/portal/grafana/public/img/fav32.png", matches: true},
		{pattern: "/ops/portal/grafana/**", url: "/ops/portal/grafana/public/build/runtime.3932bda029d2299a9d96.js", matches: true},
	}
	features.EnableV3URLPatternMatchin()
	for _, c := range testCases {
		if !assert.Equal(t, c.matches, URLMatchesWildcardPattern(c.url, c.pattern)) {
			t.Logf("URLMatchesWildcardPattern(%v, %v) != %v", c.url, c.pattern, c.matches)
		}
	}
}

func TestRegexpMatches(t *testing.T) {
	type test struct {
		pattern string
		url     string
		matches bool
	}

	var testCases = []test{
		{pattern: ``, url: "", matches: false},
		{pattern: ``, url: "/", matches: false},
		{pattern: `/`, url: "", matches: false},
		{pattern: `/`, url: "/", matches: true},
		{pattern: `https?://(my|our)domain.com/`, url: "http://mydomain.com/", matches: true},
		{pattern: `https?://(my|our)domain.com/`, url: "https://mydomain.com/", matches: true},
		{pattern: `https?://(my|our)domain.com/`, url: "http://ourdomain.com/", matches: true},
		{pattern: `https?://(my|our)domain.com/`, url: "http://ourdomain.com/admin", matches: true},
		{pattern: `https?://(my|our)domain.com/`, url: "http://theirdomain.com/", matches: false},
		// remember such regexp matches pattern anywhere in the URL unless anchored!
		{pattern: `https?://(my|our)domain.com/`, url: "http://safedomain.com/?fakestring=http://mydomain.com/", matches: true},
		// same here, it matches this generic /admin pattern anywhere in the URL
		{pattern: `/admin`, url: "https://theirdomain.com/admin", matches: true},
		{pattern: `/admin`, url: "https://theirdomain.com/admin/res/logo.jpg", matches: true},
		// can be anchored like an Nginx location block for PHP
		{pattern: `\.php$`, url: "https://theirdomain.com/survey/index.php", matches: true},
		{pattern: `\.php$`, url: "https://theirdomain.com/survey/index.php/extra/path", matches: false},
		{pattern: `^https?://ourdomain.com/admin/.*`, url: "https://ourdomain.com/admin/", matches: true},
		{pattern: `^https?://ourdomain.com/admin/.*`, url: "https://ourdomain.com/admin/users", matches: true},
		{pattern: `^https?://ourdomain.com/admin/.*`, url: "https://ourdomain.com/admin/static/theme.css", matches: true},
		{pattern: `^https?://ourdomain.com/admin/.*`, url: "https://ourdomain.com/", matches: false},
		{pattern: `^https?://ourdomain.com/admin/.*`, url: "https://ourdomain.com/about-us/", matches: false},
		{pattern: `^https?://[^./]+.com/admin/.*`, url: "https://ourdomain.com/about-us/", matches: false},
		{pattern: `^https?://[^./]+.com/admin/.*`, url: "https://ourdomain.com/admin/", matches: true},
		{pattern: `^https?://[^./]+.com/admin/.*`, url: "https://google.com/about-us/", matches: false},
		{pattern: `^https?://[^./]+.com/admin/.*`, url: "https://google.com/admin/", matches: true},
		{pattern: `^https?://[^./]+.com/admin/.*`, url: "https://eff.org/admin/", matches: false},
		{pattern: `^https?://[^/]+/`, url: "https://www.google.com/", matches: true},
	}

	features.EnableV3URLPatternMatchin()
	for _, c := range testCases {
		if !assert.Equal(t, c.matches, URLMatchesRegexp(c.url, c.pattern)) {
			t.Logf("URLMatchesRegexp(%v, %v) != %v", c.url, c.pattern, c.matches)
		}
	}
}

func TestOldPreV3Matching(t *testing.T) {
	type test struct {
		pattern string
		url     string
		matches bool
	}

	var testCases = []test{
		{pattern: ``, url: "", matches: false},
		{pattern: ``, url: "/", matches: false},
		{pattern: `/`, url: "", matches: false},
		{pattern: `/`, url: "/", matches: true},
		{pattern: `/admin/*`, url: "/admin/sub1/sub2/index.html", matches: true},
		{pattern: `/admin'`, url: "/admin/sub1/sub2/index.html", matches: false},
	}
	for _, c := range testCases {
		if !assert.Equal(t, c.matches, URLMatchesRegexp(c.url, c.pattern)) {
			t.Logf("URLMatchesRegexp(%v, %v) != %v", c.url, c.pattern, c.matches)
		}
	}
}
