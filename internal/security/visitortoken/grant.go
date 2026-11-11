package visitortoken

import (
	"crypto/sha256"
	"encoding/base64"
	"maps"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

type GrantVerifier struct {
	Digest    [32]byte
	ExpiresAt time.Time
	Kind      string
}

func GrantToken(id string, secret []byte) (Token, error) {
	if !opaqueid.Valid(id, "shg_") || len(secret) != 32 {
		return "", ErrToken
	}
	return Token("vsg1." + id + "." + base64.RawURLEncoding.EncodeToString(secret)), nil
}

// GrantTokenDigest validates the one service credential used by HTTP and control.
// its domain-separated verifier cannot substitute for a public URL share secret.
func GrantTokenDigest(token Token) (string, [32]byte, error) {
	var zero [32]byte
	if len(token) > MaxTokenBytes {
		return "", zero, ErrToken
	}
	parts := strings.Split(token.Reveal(), ".")
	if len(parts) != 3 || parts[0] != "vsg1" || !opaqueid.Valid(parts[1], "shg_") || len(parts[2]) != 43 {
		return "", zero, ErrToken
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != parts[2] {
		return "", zero, ErrToken
	}
	return parts[1], sha256.Sum256([]byte("tnl service grant v1\x00" + token.Reveal())), nil
}

func (v View) WithGrantVerifiers(verifiers map[string]GrantVerifier) View {
	v.grants = maps.Clone(verifiers)
	return v
}

func (v View) ValidGrantVerifiers() bool {
	if len(v.grants) > 256 || len(v.grants) != 0 && v.Scope.Kind != visitorscope.Service {
		return false
	}
	for id, verifier := range v.grants {
		if !(Grant{GrantID: id, Kind: verifier.Kind}).valid() || verifier.Digest == ([32]byte{}) || verifier.ExpiresAt.IsZero() {
			return false
		}
	}
	return true
}

func verifyGrantBearer(token Token, view View, now time.Time) (VerifiedPermission, error) {
	if !view.current(now) {
		return VerifiedPermission{}, ErrPolicy
	}
	id, digest, err := GrantTokenDigest(token)
	if err != nil {
		return VerifiedPermission{}, err
	}
	verifier, found := view.grants[id]
	if !found {
		return VerifiedPermission{}, ErrToken
	}
	return verifyPossession(Grant{GrantID: id, Kind: verifier.Kind}, digest, view, now)
}
