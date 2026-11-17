package daemon

import (
	"net/netip"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/storagekey"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
)

// fixtures use one known storage key without rotation. derive the expected
// service-scoped verifier rather than expecting control to retain the raw address.
func runtimeSourceDigest(t *testing.T, purpose, service, source string) string {
	t.Helper()
	keys, err := storagekey.New(testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.IPPolicyKey(keys.CurrentID(), purpose+":"+service)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key[:])
	digest, err := ippolicy.HashAddress(key, netip.MustParseAddr(source))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
