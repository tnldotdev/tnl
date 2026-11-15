package local

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type deploymentInvocation struct {
	native    *publisheridentity.Native
	profile   *clientstate.Store
	service   controlv1.Service
	cleanup   func() error
	expiresAt time.Time
}

// deployment authority never selects local configuration or a publisher file.
// the existing invocation manager owns the worker and its exact allocation.
func (a *appRuntime) prepareDeploymentInvocation(ctx context.Context, r publisherprotocol.Invocation) (result deploymentInvocation, err error) {
	selection := r.Deployment
	if selection == nil || r.ServerUrl != nil || r.PublisherCredentialFile != "" || r.PublisherIdentityId != "" || selection.Service != "" && (r.AccessMode != nil || r.Ip != nil || r.Limits != nil || r.RequirePostQuantum != nil) {
		return result, publisheridentity.ErrScope
	}
	credential, err := auth.ParseDeploymentCredential(selection.Credential)
	if err != nil {
		return result, err
	}
	if err := credential.SelectProject(selection.Project); err != nil {
		return result, err
	}
	result.expiresAt = credential.Approval.ExpiresAt
	result.profile, err = a.state.Server(ctx, credential.ControlURL)
	if err != nil {
		return result, err
	}
	control, err := clientcontrol.New(credential.ControlURL, nil, "")
	if err != nil {
		return result, err
	}
	authority, err := clientauthority.New(credential.ControlURL, nil, "")
	if err != nil {
		return result, err
	}
	private, err := base64.RawURLEncoding.DecodeString(credential.PrivateKey)
	if err != nil {
		return result, auth.ErrDeploymentCredential
	}
	key := ed25519.PrivateKey(private)
	if selection.Service != "" {
		native, service, err := publisheridentity.PrepareDeployment(ctx, control, authority, credential.Approval, key, selection.Name, selection.Service)
		if err != nil {
			return result, err
		}
		result.native, result.service = native, *service
		// named publication borrows a retained service; it never owns deletion.
		result.cleanup = invocationCleanup(nil, result.expiresAt)
		return result, nil
	}
	allocation, err := invocationAllocation(r)
	if err != nil {
		return result, err
	}
	// every recovery uses the captured approval and fixed original deadline.
	// no fresh identity, grant, invocation, or extended expiration is invented.
	allocation.ExpiresAt = new(result.expiresAt)
	native, service, err := publisheridentity.PrepareDeploymentAllocation(ctx, control, authority, credential.Approval, key, selection.Name, allocation)
	if native == nil {
		// only the native owner can distinguish an attempted uncertain reply
		// from pre-attempt failure or already confirmed allocation cleanup.
		return result, err
	}
	result.cleanup = invocationCleanup(func(ctx context.Context) error {
		if service != nil {
			return native.DeleteAllocatedService(ctx, service.Id)
		}
		recovered, observed, recoveryErr := publisheridentity.PrepareDeploymentAllocation(ctx, control, authority, credential.Approval, key, selection.Name, allocation)
		if recovered == nil || observed == nil {
			return recoveryErr
		}
		native, service = recovered, observed
		return errors.Join(recoveryErr, native.DeleteAllocatedService(ctx, service.Id))
	}, result.expiresAt)
	if err == nil {
		result.native, result.service = native, *service
	}
	return result, err
}
