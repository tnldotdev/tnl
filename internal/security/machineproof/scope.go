// package machineproof binds registered machine proofs to one authority operation.
// publisherproof owns signing, verification, lifetime bounds and key parsing.
package machineproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// scopes are "machine/v1/" plus lowercase hex SHA-256 of the compact JSON string
// array. Workload embeds the compact services array as its last string; nil is
// the string "null", distinct from "[]". preserve selector order when signing.
func scope(values ...string) string {
	b, _ := json.Marshal(values)
	d := sha256.Sum256(b)
	return "machine/v1/" + hex.EncodeToString(d[:])
}

func Provisioning(grant, operation string) string {
	return scope("provisioning", grant, operation)
}

// use publisherproof.Sign(machineID, keyID, Provisioning(grant, operation),
// controlURL+"/v1/provisioning-sessions/exchange", privateKey, now). publisherproof
// writes the scope into grant_id and signs exact iss=sub=machineID, aud, jti,
// iat and exp, with an EdDSA/JWT header and kid. never reuse a signing jti.

// exchange proofs include the ephemeral public key, nonce and exact service
// selectors. resolution uses empty exchange fields and the resolve operation.
func Workload(group, workload, operation, publicKey, nonce string, services []string) string {
	b, _ := json.Marshal(services)
	return scope("workload", group, workload, operation, publicKey, nonce, string(b))
}
