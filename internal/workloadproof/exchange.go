// package workloadproof defines the native exchange's key-possession proof.
package workloadproof

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
)

// Digest binds the key signature to the tenant, project, explicit policy,
// assertion and requested subset. caller order never changes the service set.
func Digest(team, project, ci string, assertion [32]byte, services []string) []byte {
	services = slices.Clone(services)
	slices.Sort(services)
	data, _ := json.Marshal([]any{"tnl-workload-exchange/v1", team, project, ci, assertion, services})
	digest := sha256.Sum256(data)
	return digest[:]
}
