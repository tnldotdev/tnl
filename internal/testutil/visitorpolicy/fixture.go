// package visitorpolicy supplies bounded generated-wire fixtures for policy HTTP
// and publisher consumer tests. it contains no production validation rules.
package visitorpolicy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func ObservationIDs() []string {
	ids := make([]string, 2048)
	for i := range ids {
		ids[i] = fmt.Sprintf("salloc_%022d", i)
	}
	return ids
}

func Observations(run string, number int64, until time.Time) []controlv1.StreamCapacityObservation {
	until = until.UTC()
	observed := make([]controlv1.StreamCapacityObservation, 2048)
	for index, id := range ObservationIDs() {
		observed[index] = controlv1.StreamCapacityObservation{AllocationId: id, RunId: run, RunNumber: number, ValidUntil: until}
	}
	return observed
}

func Maximum(t testing.TB, now time.Time) (controlv1.VisitorPolicyUpdate, ed25519.PrivateKey) {
	t.Helper()
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
	digest, err := visitortoken.KeyDigest(private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	scope := controlv1.VisitorResourceScope{Kind: "service", Id: "svc_" + strings.Repeat("A", 22)}
	policy := controlv1.VisitorPolicySnapshot{
		Resource: scope, Hostname: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61),
		Issuer: "https://" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 56),
		Port:   65535, VisitorPolicyRevision: 1, KeyRevision: math.MaxInt64,
		ObservedAt: now, ValidUntil: now.Add(10 * time.Second), Enabled: true,
		VerificationKeys:  make([]controlv1.VisitorVerificationKey, 64),
		WorkloadLeases:    make([]controlv1.VisitorWorkloadLease, 4096),
		StreamAllocations: make([]controlv1.StreamCapacityAllocation, 2048),
	}
	for i := range policy.VerificationKeys {
		policy.VerificationKeys[i] = controlv1.VisitorVerificationKey{Id: strings.Repeat("\x01", 126) + fmt.Sprintf("%02d", i), PublicKey: private.Public().(ed25519.PublicKey)}
	}
	// keep one maximum-length key ID usable inside the separate 2 KiB token
	// budget; the other IDs still exercise six-byte JSON character escaping.
	policy.VerificationKeys[0].Id = strings.Repeat("k", 128)
	for i := range policy.WorkloadLeases {
		policy.WorkloadLeases[i] = controlv1.VisitorWorkloadLease{SessionId: fmt.Sprintf("wls_%022d", i), KeySha256: digest, ExpiresAt: now.Add(time.Minute)}
	}
	var hashKey [32]byte
	hashKey[0] = 1
	policy.Ip = &controlv1.VisitorPolicyIP{Key: hashKey[:], Prefixes: make([]controlv1.HashedIPPrefix, 2048)}
	for i, id := range ObservationIDs() {
		reservationKey := sha256.Sum256([]byte(id))
		policy.StreamAllocations[i] = controlv1.StreamCapacityAllocation{
			Id: id, Resource: scope, RunId: "srun_" + strings.Repeat("B", 22), RunNumber: math.MaxInt64,
			IngressId: strings.Repeat("\x01", 128), IngressRunId: strings.Repeat("\x02", 128), IngressLeaseRevision: math.MaxInt64,
			Capacity: 1 << 20, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), PublisherObserved: true, PublisherObservedUntil: new(now.Add(10 * time.Second)),
			ReservationKey: reservationKey[:],
		}
		entry, err := ippolicy.Hash(hashKey, netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)}), 32))
		if err != nil {
			t.Fatal(err)
		}
		policy.Ip.Prefixes[i] = controlv1.HashedIPPrefix{Family: controlv1.HashedIPPrefixFamily(entry.Family), PrefixLength: entry.Bits, Digest: entry.Digest}
	}
	return controlv1.VisitorPolicyUpdate{Policy: policy, Revisions: []int64{}, SnapshotRequired: true}, private
}
