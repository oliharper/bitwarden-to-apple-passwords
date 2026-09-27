package verifier

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// baseDomain is a lookup key only. It never identifies an account.
func baseDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return ""
	}
	if host == "localhost" || net.ParseIP(host) != nil {
		return host
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return domain
}
