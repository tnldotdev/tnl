package naming

import (
	"errors"
	"strings"

	"golang.org/x/net/publicsuffix"
)

var ErrUnclaimableDomain = errors.New("naming: domain is not claimable")

// IsWithin reports whether hostname is base or a label-boundary descendant.
func IsWithin(hostname, base string) bool {
	return hostname == base || strings.HasSuffix(hostname, "."+base)
}

// ChildDepth returns the number of labels to the left of base.
func ChildDepth(hostname, base string) (int, bool) {
	if hostname == base {
		return 0, true
	}
	relative, found := strings.CutSuffix(hostname, "."+base)
	if !found || relative == "" {
		return 0, false
	}
	return strings.Count(relative, ".") + 1, true
}

// CustomDomain validates an absolute BYO domain against the pinned x/net PSL,
// including its private section. The returned boolean identifies a zone apex.
func CustomDomain(input, hostnameSuffix string) (string, bool, error) {
	domain, err := CanonicalizeHostname(input)
	if err != nil {
		return "", false, err
	}
	suffix, err := CanonicalizeHostname(hostnameSuffix)
	if err != nil {
		return "", false, err
	}
	if IsWithin(domain, suffix) || IsWithin(suffix, domain) {
		return "", false, ErrUnclaimableDomain
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", false, ErrUnclaimableDomain
	}
	return domain, domain == registrable, nil
}
