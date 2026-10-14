// package readinessproof derives a short-lived public probe credential for one publish run.
package readinessproof

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
)

// ForRun separates the proof for each run while keeping the local publisher's
// random seed in memory, away from client state and runtime snapshots.
func ForRun(seed string, number uint64) string {
	if seed == "" || number == 0 {
		return ""
	}
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], number)
	mac := hmac.New(sha256.New, []byte(seed))
	_, _ = mac.Write([]byte("tnl:readiness:run\x00"))
	_, _ = mac.Write(version[:])
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
