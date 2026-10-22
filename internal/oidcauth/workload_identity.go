package oidcauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// IdentityDigest is called only with verifier-produced executions. assertion
// timestamps and JTI rotate; immutable provider identity and job provenance do not.
func (c WorkloadExecution) IdentityDigest() string {
	c.IssuedAt, c.NotBefore, c.ExpiresAt = 0, 0, 0
	c.AssertionDigest = [32]byte{}
	if c.GitHub != nil {
		g := *c.GitHub
		g.JTI, g.IssuedAt, g.NotBefore, g.ExpiresAt = "", 0, 0, 0
		g.AssertionDigest = [32]byte{}
		c.GitHub = &g
	}
	b, _ := json.Marshal(c)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
