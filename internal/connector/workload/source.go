package workload

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/tnldotdev/tnl/internal/security/machineproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

// sourceChallenge exposes only public proof facts from this retained native
// tuple. the owner supplies its private-process binding and original selection.
func (c *Client) SourceChallenge(source authorityv1.IdentitySourceSelection, selection authorityv1.IdentitySourceVisitorSelection, owner string, now time.Time) (authorityv1.IdentitySourceChallenge, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	challenge := authorityv1.IdentitySourceChallenge{Schema: 1, Source: source, Server: c.server, NativePublicKey: base64.RawURLEncoding.EncodeToString(c.PublicKey()), Selection: &selection, ExpiresAt: now.Add(time.Minute), Operation: "visitor_prepare", Nonce: c.nonce}
	operation, nonce := "prepare", c.nonce
	challenge.Audience = c.server + "/v1/projects/" + selection.Environment.ProjectKey + "/environments/" + selection.Environment.EnvironmentId + "/visitors/prepare"
	if c.session.Id != "" {
		if !c.session.LeaseExpiresAt.After(now) || !SessionDeadline(c.session).After(now) {
			return authorityv1.IdentitySourceChallenge{}, ErrSessionExpired
		}
		operation, nonce = "attach", c.session.Id
		challenge.Operation, challenge.Nonce, challenge.SessionId = "visitor_attach", "", c.session.Id
		challenge.Audience = c.server + "/v1/environment-visitor-sessions/" + c.session.Id + "/assertions"
		for _, fence := range []time.Time{c.session.LeaseExpiresAt, SessionDeadline(c.session)} {
			if fence.Before(challenge.ExpiresAt) { challenge.ExpiresAt = fence }
		}
	}
	services := make(map[string]string, len(selection.Services))
	for name, protocol := range selection.Services { services[name] = string(protocol) }
	challenge.Scope = machineproof.EnvironmentVisitor(selection.PermissionId, selection.Environment.EnvironmentId, operation, challenge.NativePublicKey, nonce, services)
	encoded, _ := json.Marshal([]any{owner, source, selection, challenge.NativePublicKey, operation, nonce})
	digest := sha256.Sum256(encoded)
	challenge.BindingDigest = hex.EncodeToString(digest[:])
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil { return authorityv1.IdentitySourceChallenge{}, err }
	challenge.Id = hex.EncodeToString(id[:])
	if err := machineproof.ValidateSourceChallenge(challenge, now); err != nil { return authorityv1.IdentitySourceChallenge{}, err }
	return challenge, nil
}
