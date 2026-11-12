package state

import (
	"crypto/sha256"
	"encoding/json"
	"sort"

	"github.com/tnldotdev/tnl/internal/region"
)

// region preferences are part of the retry identity and are stored with the run
// so a later control process applies the same policy during recovery.
func regionRequestDigest(base [32]byte, preferences []string) [32]byte {
	value, _ := json.Marshal(preferences)
	h := sha256.New()
	_, _ = h.Write([]byte("tnl:region-preferences:v1\x00"))
	_, _ = h.Write(base[:])
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(value)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func rankRelayPlacements(services []relayServicePlacement, preferences []string) {
	// availableRelayServicePlacements already orders load and stable IDs.
	sort.SliceStable(services, func(i, j int) bool {
		return region.Rank(preferences, services[i].region) < region.Rank(preferences, services[j].region)
	})
}
