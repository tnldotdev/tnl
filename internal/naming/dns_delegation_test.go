package naming

import (
	"strings"
	"testing"
)

func TestDomainClaimProofPlacement(t *testing.T) {
	for _, item := range []struct {
		domain, want string
		apex         bool
	}{
		{"dev.example.com", "_tnl-claim-dev.example.com", false},
		{"example.com", "_tnl-claim.example.com", true},
		{"one.two.example.com", "_tnl-claim-one.two.example.com", false},
		{strings.Repeat("x", 63) + ".example.com", "", false},
	} {
		got, err := DomainClaimProof(item.domain, item.apex)
		if err != nil || IsWithin(got, item.domain) != item.apex ||
			item.want != "" && got != item.want || len(strings.SplitN(got, ".", 2)[0]) > MaxLabelBytes {
			t.Fatalf("proof for %s = %q / %v", item.domain, got, err)
		}
	}
}
