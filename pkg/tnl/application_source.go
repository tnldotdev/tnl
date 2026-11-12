package tnl

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	localv1 "github.com/tnldotdev/tnl/pkg/api/publisher/local/v1"
)

type applicationProof struct {
	auth                        json.RawMessage
	expiresAt, deliveryDeadline time.Time
}

func (applicationProof) String() string   { return "private application source reply" }
func (applicationProof) GoString() string { return "private application source reply" }

type applicationNativeTuple struct{ public, nonce, session string }

func acquireApplicationSource(ctx context.Context, endpoint publisherprotocol.Endpoint, request publisherprotocol.ApplicationPublication, identity *PublisherIdentity, fence time.Time, tuple *applicationNativeTuple) (applicationProof, error) {
	if identity.registered == nil {
		proof, err := acquireApplicationProof(ctx, identity.source, fence)
		if err != nil {
			return applicationProof{}, err
		}
		encoded, err := json.Marshal(localv1.ApplicationOIDCProof{Kind: "oidc", MachineId: identity.source.MachineID, Assertion: proof.Token})
		return applicationProof{auth: encoded, expiresAt: proof.ExpiresAt, deliveryDeadline: proof.ExpiresAt}, err
	}
	source := identity.registered
	encoded, err := json.Marshal(localv1.ApplicationRegisteredKeyProof{Kind: "registered_key", MachineId: source.selection.MachineId, KeyId: source.selection.KeyId})
	if err != nil {
		return applicationProof{}, err
	}
	defer clear(encoded)
	request.Auth = encoded
	deadline := time.Now().Add(30 * time.Second)
	if !fence.IsZero() && fence.Before(deadline) {
		deadline = fence
	}
	acquire, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var challenge authorityv1.IdentitySourceChallenge
	if err := publisherprotocol.Call(acquire, endpoint, "POST", "/v1/identity-source-challenges", request, &challenge); err != nil {
		return applicationProof{}, errors.Join(context.Cause(acquire), err)
	}
	if err := validateApplicationSourceChallenge(challenge, request, identity, tuple); err != nil {
		return applicationProof{}, err
	}
	reply, expiry, err := signApplicationSourceChallenge(acquire, source, challenge)
	if err != nil {
		return applicationProof{}, err
	}
	auth, err := json.Marshal(localv1.ApplicationRegisteredKeyProof{Kind: "registered_key", MachineId: source.selection.MachineId, KeyId: source.selection.KeyId, Reply: &reply})
	return applicationProof{auth: auth, expiresAt: expiry, deliveryDeadline: challenge.ExpiresAt}, err
}

func validateApplicationSourceChallenge(c authorityv1.IdentitySourceChallenge, request publisherprotocol.ApplicationPublication, identity *PublisherIdentity, tuple *applicationNativeTuple) error {
	if err := machineproof.ValidateSourceChallenge(c, time.Now()); err != nil {
		return err
	}
	if identity.registered == nil || c.Source != identity.registered.selection || c.Server != identity.server || c.Publication == nil || c.Selection != nil || c.Publication.Resource != valueOrEmpty(request.ResourceId) || c.Publication.Namespace != applicationNamespace(request) || (c.Operation != "publication_exchange" && c.Operation != "publication_refresh") {
		return ErrPublisherScope
	}
	if tuple.public != "" && tuple.public != c.NativePublicKey || c.Operation == "publication_exchange" && tuple.nonce != "" && tuple.nonce != c.Nonce || c.Operation == "publication_refresh" && tuple.session != "" && tuple.session != c.SessionId {
		return ErrPublisherScope
	}
	tuple.public = c.NativePublicKey
	if c.Operation == "publication_exchange" {
		tuple.nonce = c.Nonce
	} else {
		tuple.session = c.SessionId
	}
	return nil
}

func signApplicationSourceChallenge(ctx context.Context, source *registeredApplicationSource, challenge authorityv1.IdentitySourceChallenge) (authorityv1.IdentitySourceReply, time.Time, error) {
	if source == nil || source.sign == nil || challenge.Source != source.selection || machineproof.ValidateSourceChallenge(challenge, time.Now()) != nil {
		return authorityv1.IdentitySourceReply{}, time.Time{}, ErrPublisherScope
	}
	signing, cancel := context.WithDeadline(ctx, challenge.ExpiresAt)
	defer cancel()
	if err := context.Cause(signing); err != nil {
		return authorityv1.IdentitySourceReply{}, time.Time{}, err
	}
	assertion, expiry, err := source.sign(signing, challenge)
	if err := errors.Join(context.Cause(signing), err); err != nil {
		return authorityv1.IdentitySourceReply{}, time.Time{}, err
	}
	if !expiry.After(time.Now().Add(5 * time.Second)) {
		return authorityv1.IdentitySourceReply{}, time.Time{}, ErrPublisherScope
	}
	return authorityv1.IdentitySourceReply{Schema: 1, ChallengeId: challenge.Id, Assertion: assertion}, expiry, nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func applicationNamespace(request publisherprotocol.ApplicationPublication) string {
	if request.Allocate == nil {
		return ""
	}
	return request.Allocate.Namespace
}

func deliverApplicationProof(ctx context.Context, endpoint publisherprotocol.Endpoint, request publisherprotocol.ApplicationPublication, proof applicationProof) (publisherprotocol.AcceptedPublication, error) {
	defer clear(proof.auth)
	request.Auth = proof.auth
	bounded, cancel := context.WithDeadline(ctx, proof.deliveryDeadline)
	defer cancel()
	var accepted publisherprotocol.AcceptedPublication
	err := publisherprotocol.Call(bounded, endpoint, "POST", "/v1/publications", request, &accepted)
	return accepted, errors.Join(context.Cause(bounded), err)
}
