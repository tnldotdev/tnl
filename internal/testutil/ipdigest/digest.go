// package ipdigest supplies deterministic exact-IP digests for policy fixtures.
package ipdigest

import (
	"net/netip"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
)

func Key() []byte {
	key := [32]byte{1}
	return key[:]
}

func Hash(address string) string {
	digest, err := ippolicy.HashAddress([32]byte(Key()), netip.MustParseAddr(address))
	if err != nil {
		panic(err)
	}
	return digest
}
