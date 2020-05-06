package util

import (
	"fmt"
	"strings"
)

// CookieDomain represents a top-level cookie domain and helper functions on it
type CookieDomain struct {
	Domain       string `description:"TEST1"`
	DomainLen    int    `description:"TEST2"`
	SubDomain    string `description:"TEST3"`
	SubDomainLen int    `description:"TEST4"`
}

// CookieDomains holds a list of cookie domains
type CookieDomains []CookieDomain

func NewCookieDomain(domain string) *CookieDomain {
	return &CookieDomain{
		Domain:       domain,
		DomainLen:    len(domain),
		SubDomain:    fmt.Sprintf(".%s", domain),
		SubDomainLen: len(domain) + 1,
	}
}

// Match returns true if host matches the CookieDomain or is a subdomain of it
func (c CookieDomain) Match(host string) bool {
	// Exact domain match?
	if host == c.Domain {
		return true
	}

	// Subdomain match?
	if len(host) >= c.SubDomainLen && host[len(host)-c.SubDomainLen:] == c.SubDomain {
		return true
	}

	return false
}

// UnmarshalFlag unmarshals the CookieDomain from the flag string
func (c *CookieDomain) UnmarshalFlag(value string) error {
	*c = *NewCookieDomain(value)
	return nil
}

// MarshalFlag marshals the CookieDomain into a flag string
func (c *CookieDomain) MarshalFlag() (string, error) {
	return c.Domain, nil
}

// Legacy support for comma separated list of cookie domains

// UnmarshalFlag unmarshals the CookieDomains from the flag string
func (c *CookieDomains) UnmarshalFlag(value string) error {
	if len(value) > 0 {
		for _, d := range strings.Split(value, ",") {
			cookieDomain := NewCookieDomain(d)
			*c = append(*c, *cookieDomain)
		}
	}
	return nil
}

// MarshalFlag marshals the CookieDomain into a flag string
func (c *CookieDomains) MarshalFlag() (string, error) {
	var domains []string
	for _, d := range *c {
		domains = append(domains, d.Domain)
	}
	return strings.Join(domains, ","), nil
}
