package naming

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

func ValidDelegationSetID(id string) bool {
	if len(id) < 2 || len(id) > 64 || id[0] != 'N' {
		return false
	}
	for _, c := range id[1:] {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func BrandedNameservers(domain string) ([]string, error) {
	names := make([]string, 4)
	for i := range names {
		host := "ns" + strconv.Itoa(i+1) + "." + domain
		if canonical, err := CanonicalizeHostname(host); err != nil || canonical != host {
			return nil, errors.New("nameserver domain cannot form canonical ns1 through ns4 hostnames")
		}
		names[i] = host
	}
	return names, nil
}

// DomainClaimProof puts a subdomain's proof beside, not beneath, the delegation.
// a registrable domain must be verified at its current provider before delegation.
func DomainClaimProof(domain string, apex bool) (string, error) {
	if apex {
		proof := "_tnl-claim." + domain
		if len(proof) <= MaxHostnameBytes {
			return proof, nil
		}
	} else if label, parent, ok := strings.Cut(domain, "."); ok {
		proof := "_tnl-claim-" + label + "." + parent
		if len(label)+len("_tnl-claim-") <= MaxLabelBytes && len(proof) <= MaxHostnameBytes {
			return proof, nil
		}
		digest := sha256.Sum256([]byte(domain))
		proof = "_tnl-" + hex.EncodeToString(digest[:12]) + "." + parent
		if len(proof) <= MaxHostnameBytes {
			return proof, nil
		}
	}
	return "", ErrUnclaimableDomain
}
