package publisheridentity

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// RuntimeScope binds the complete lifecycle request into the one-use assertion.
// the distinct audience prevents a verification or publication proof being used
// as a runtime start, or a proof being replayed with another process or epoch.
func RuntimeScope(scope, action, run string, epoch int64) string {
	digest := sha256.Sum256([]byte("tnl publisher runtime v1\x00" + scope + "\x00" + action + "\x00" + run + "\x00" + strconv.FormatInt(epoch, 10)))
	return "runtime:" + hex.EncodeToString(digest[:])
}
