package util

import (
	"fmt"
	"strings"
)

// CookieDomain
type CookieDomain struct {
	Domain       string `description:"TEST1"`
	DomainLen    int    `description:"TEST2"`
	SubDomain    string `description:"TEST3"`
	SubDomainLen int    `description:"TEST4"`
}

type CookieDomains []CookieDomain

func NewCookieDomain(domain string) *CookieDomain {
	return &CookieDomain{
		Domain:       domain,
		DomainLen:    len(domain),
		SubDomain:    fmt.Sprintf(".%s", domain),
		SubDomainLen: len(domain) + 1,
	}
}

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

func (c *CookieDomain) UnmarshalFlag(value string) error {
	*c = *NewCookieDomain(value)
	return nil
}

func (c *CookieDomain) MarshalFlag() (string, error) {
	return c.Domain, nil
}

// Legacy support for comma separated list of cookie domains

func (c *CookieDomains) UnmarshalFlag(value string) error {
	if len(value) > 0 {
		for _, d := range strings.Split(value, ",") {
			cookieDomain := NewCookieDomain(d)
			*c = append(*c, *cookieDomain)
		}
	}
	return nil
}

func (c *CookieDomains) MarshalFlag() (string, error) {
	var domains []string
	for _, d := range *c {
		domains = append(domains, d.Domain)
	}
	return strings.Join(domains, ","), nil
}
