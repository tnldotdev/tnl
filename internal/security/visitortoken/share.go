package visitortoken

import (
	"crypto/sha256"
	"crypto/subtle"
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
	verifier, found := view.shares[id]
	if !found || view.Scope.Kind != visitorscope.PublicURL || subtle.ConstantTimeCompare(digest[:], verifier.Digest[:]) != 1 || !verifier.ExpiresAt.After(view.AuthorityTime(now)) {
		return VerifiedPermission{}, ErrToken
	}
	permission := VerifiedPermission{facts: Permission{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision, Subject: Share{ShareID: id}, ExpiresAt: verifier.ExpiresAt}, shareDigest: digest}
	if err := checkShareCurrent(permission, view, now); err != nil {
		return VerifiedPermission{}, err
	}
	return permission, nil
}

func checkShareCurrent(permission VerifiedPermission, view View, now time.Time) error {
	if !view.current(now) {
		return ErrPolicy
	}
	facts := permission.facts
	share, ok := facts.Subject.(Share)
	verifier, found := view.shares[share.ShareID]
	if !ok || !found || view.Scope.Kind != visitorscope.PublicURL || facts.Scope != view.Scope || facts.Hostname != view.Hostname || facts.Port != view.Port ||
		permission.shareDigest == ([32]byte{}) || subtle.ConstantTimeCompare(permission.shareDigest[:], verifier.Digest[:]) != 1 ||
		!facts.ExpiresAt.After(view.AuthorityTime(now)) || !verifier.ExpiresAt.After(view.AuthorityTime(now)) {
		return ErrToken
	}
	return nil
}

// PermissionDeadline preserves the admitted credential's lifetime while applying
// a shorter current parent deadline. policy renewal never widens an admission.
func PermissionDeadline(permission VerifiedPermission, view View) time.Time {
	until := permission.facts.ExpiresAt
	if permission.shareDigest != ([32]byte{}) {
		if share, ok := permission.facts.Subject.(Share); ok {
			if parent, found := view.shares[share.ShareID]; found && parent.ExpiresAt.Before(until) {
				until = parent.ExpiresAt
			}
		}
	}
	return until
}
