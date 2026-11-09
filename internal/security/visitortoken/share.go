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

// ShareVerifier is current control-authorized possession evidence. it contains
// only a verifier, never the secret carried by a share link or bearer token.
type ShareVerifier struct {
	Digest    [sha256.Size]byte
	ExpiresAt time.Time
}

// ShareToken packages the existing share secret for direct HTTP use. its lifetime
// and current resource scope come from control's short-lived policy projection.
func ShareToken(id string, secret []byte) (Token, error) {
	if !opaqueid.Valid(id, opaqueid.SharePrefix) || len(secret) != 32 {
		return "", ErrToken
	}
	return Token("vsh1." + id + "." + base64.RawURLEncoding.EncodeToString(secret)), nil
}

func parseShareToken(token Token) (string, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if len(token) > MaxTokenBytes {
		return "", zero, ErrToken
	}
	parts := strings.Split(token.Reveal(), ".")
	if len(parts) != 3 || parts[0] != "vsh1" || !opaqueid.Valid(parts[1], opaqueid.SharePrefix) || len(parts[2]) != 43 {
		return "", zero, ErrToken
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != parts[2] {
		return "", zero, ErrToken
	}
	return parts[1], sha256.Sum256(secret), nil
}

func (v View) WithShareVerifiers(verifiers map[string]ShareVerifier) View {
	v.shares = maps.Clone(verifiers)
	return v
}

func (v View) ValidShareVerifiers() bool {
	if len(v.shares) > 256 || len(v.shares) != 0 && v.Scope.Kind != visitorscope.PublicURL {
		return false
	}
	for id, verifier := range v.shares {
		if !opaqueid.Valid(id, opaqueid.SharePrefix) || verifier.Digest == ([32]byte{}) || verifier.ExpiresAt.IsZero() {
			return false
		}
	}
	return true
}

func verifyShareBearer(token Token, view View, now time.Time) (VerifiedPermission, error) {
	if !view.current(now) {
		return VerifiedPermission{}, ErrPolicy
	}
	id, digest, err := parseShareToken(token)
	if err != nil {
		return VerifiedPermission{}, err
	}
	return verifyPossession(Share{ShareID: id}, digest, view, now)
}
