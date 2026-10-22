// package workloadproof defines the native exchange's key-possession proof.
package workloadproof

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
)

// exchange binds the key signature to the deployment, saved policy, retry nonce,
// assertion and requested subset. caller order never changes the service set.
func Exchange(team, project, workload, source, nonce string, assertion [32]byte, services []string) []byte {
	services = slices.Clone(services)
	slices.Sort(services)
	data, _ := json.Marshal([]any{"tnl-workload-exchange/v1", team, project, source, workload, nonce, base64.RawURLEncoding.EncodeToString(assertion[:]), services})
	digest := sha256.Sum256(data)
	return digest[:]
}

func Attach(session string, assertion [32]byte) []byte {
	data, _ := json.Marshal([]string{"tnl-workload-attach/v1", session, base64.RawURLEncoding.EncodeToString(assertion[:])})
	digest := sha256.Sum256(data)
	return digest[:]
}

func ValidNonce(nonce string) bool {
	if len(nonce) < 16 || len(nonce) > 128 {
		return false
	}
	for _, c := range nonce {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}
