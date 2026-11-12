package local

import (
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"net/http"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	localv1 "github.com/tnldotdev/tnl/pkg/api/publisher/local/v1"
)

type controlApplicationAuthority struct {
	http *http.Client
}

var _ invocation.ApplicationAuthority = (*controlApplicationAuthority)(nil)
var _ invocation.ApplicationControl = (*publisheridentity.Native)(nil)

// NewControlApplicationAuthority composes only explicit source proof with the
// canonical machine-publication API. it never reads saved login or publisher
// selection, and it owns neither app listeners nor publication workers.
func NewControlApplicationAuthority(client *http.Client) invocation.ApplicationAuthority {
	return &controlApplicationAuthority{http: client}
}

func applicationOIDCProof(raw json.RawMessage) (localv1.ApplicationOIDCProof, error) {
	var proof localv1.ApplicationOIDCProof
	if jsonv2.Unmarshal(raw, &proof, jsonv2.RejectUnknownMembers(true)) != nil || proof.Kind != "oidc" || !opaqueid.Valid(proof.MachineId, "mci_") || !publisheridentity.ValidApplicationAssertion(proof.Assertion) {
		return localv1.ApplicationOIDCProof{}, publisherprotocol.ErrApplicationAuthInvalid
	}
	return proof, nil
}

func (a *controlApplicationAuthority) ResolveApplicationPublication(ctx context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
	proof, err := applicationSourceProof(selection.Auth, true)
	if err != nil {
		return invocation.ApplicationGrant{}, err
	}
	// saved URL policy is immutable through this application operation.
	if selection.ResourceID != "" && (selection.AccessMode != nil || selection.IP != nil || selection.Limits != nil) {
		return invocation.ApplicationGrant{}, publisherprotocol.ErrApplicationDenied
	}
	if selection.Publication == nil {
		return invocation.ApplicationGrant{}, publisherprotocol.ErrApplicationUnavailable
	}
	binding := selection.Publication.Binding()
	if binding.ServerURL != selection.ServerURL || binding.InvocationID != selection.InvocationID || binding.Target != selection.Target || binding.ResourceID != selection.ResourceID || binding.Namespace != selection.Namespace || binding.SourceKind != string(proof.selection.Kind) || binding.SourceMachineID != proof.selection.MachineId || binding.SourceKeyID != proof.selection.KeyId {
		return invocation.ApplicationGrant{}, publisherprotocol.ErrApplicationDenied
	}
	control, err := clientcontrol.New(selection.ServerURL, a.http, "")
	if err != nil {
		return invocation.ApplicationGrant{}, applicationAuthorityError(err)
	}
	authority, err := clientauthority.New(selection.ServerURL, a.http, "")
	if err != nil {
		return invocation.ApplicationGrant{}, applicationAuthorityError(err)
	}
	grant := invocation.ApplicationGrant{}
	retire := func(ctx context.Context) error {
		return publisheridentity.CleanupApplicationPublication(ctx, selection.Publication, authority)
	}
	if selection.Namespace != "" {
		grant.Cleanup = retire
	} else {
		grant.Release = retire
	}
	session, err := publisheridentity.OpenApplicationSession(ctx, control, authority, selection.Publication, proof.assertion)
	if err != nil {
		return grant, applicationAuthorityError(err)
	}
	native := session.Publisher()
	grant.Control, grant.PublisherIdentityID = native, native.PublisherIdentityID()
	grant.CheckServing, grant.Run = session.CheckServing, session.Run
	grant.RefreshAuth = func(ctx context.Context, raw json.RawMessage) error {
		fresh, err := applicationSourceProof(raw, true)
		if err != nil {
			return err
		}
		if fresh.selection != proof.selection {
			return publisherprotocol.ErrApplicationDenied
		}
		return applicationAuthorityError(session.Refresh(ctx, fresh.assertion))
	}
	if selection.Namespace != "" {
		// establish original-key cleanup before allocation: a failed reply is not
		// proof that control did not allocate the exact invocation tuple.
		grant.Cleanup = session.CleanupAllocation
		grant.PublicURL, err = session.Allocate(ctx, controlv1.AllocateEphemeralPublicURLRequest{InvocationId: selection.InvocationID, Target: selection.Target, AccessMode: selection.AccessMode, RequirePostQuantum: selection.RequirePostQuantum, Ip: selection.IP, Limits: selection.Limits})
	} else {
		grant.PublicURL, err = session.SavedPublicURL(ctx)
	}
	return grant, applicationAuthorityError(err)
}
