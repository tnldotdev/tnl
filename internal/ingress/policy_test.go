package ingress

import (
	"net/netip"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var policyTestKey = [32]byte{1}

func hashedPolicyForTest(t *testing.T, prefix string) *ippolicy.Policy {
	t.Helper()
	entry, err := ippolicy.Hash(policyTestKey, netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ippolicy.New(policyTestKey, []ippolicy.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	return &policy
}

func hashedRoutingPolicyForTest(t *testing.T, entry *ingressv1.IngressRoutingTableEntry, prefix string) {
	t.Helper()
	hashed, err := ippolicy.Hash(policyTestKey, netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	key := append([]byte(nil), policyTestKey[:]...)
	entry.IpPolicy = ingressv1.HashedAllowlist
	entry.AllowedIpHashes = []ingressv1.HashedIPPrefix{{
		Family: controlv1.HashedIPPrefixFamily(hashed.Family), PrefixLength: hashed.Bits, Digest: hashed.Digest,
	}}
	entry.IpPolicyKey = &key
}
