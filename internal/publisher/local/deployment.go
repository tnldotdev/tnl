package local

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	publisheradhoc "github.com/tnldotdev/tnl/internal/publisher/adhoc"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type deploymentInvocation struct {
	native    *publisheridentity.Native
	profile   *clientstate.Store
	service   controlv1.Service
	config    publisherservice.RunConfig
	cleanup   func(context.Context) error
	expiresAt time.Time
}

// deployment authority never selects local configuration or a publisher file.
// the existing invocation manager owns the worker and its exact allocation.
func (a *appRuntime) prepareDeploymentInvocation(ctx context.Context, r publisherprotocol.Invocation, options publisheradhoc.Options) (result deploymentInvocation, err error) {
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
	discovery, err := control.Discovery(ctx)
	if err != nil {
		return result, err
	}
	browserLoginAvailable := discovery.BrowserLoginAvailable != nil && *discovery.BrowserLoginAvailable
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
		if service.Endpoint == nil || !service.Endpoint.Public || service.Endpoint.Port != 443 {
			return result, publisheridentity.ErrScope
		}
		target, err := targetsyntax.ParseCanonicalTarget(r.Target)
		if err != nil {
			return result, err
		}
		trust, err := publisheridentity.ServiceTrust(*service)
		if err != nil {
			return result, err
		}
		if (target.Scheme == "https") != (trust != nil) {
			return result, publisheridentity.ErrScope
		}
		result.config = publisherservice.RunConfig{Control: native, Access: native.Access, State: result.profile,
			PublisherIdentityID: native.PublisherIdentityID(), PublisherGrantID: native.PublisherGrantID(), PublisherKeyID: native.PublisherKeyID(),
			ServiceID: service.Id, Target: target.Host, Metadata: publisheridentity.ServiceMetadata(*service), BrowserLoginAvailable: &browserLoginAvailable}
		// named publication borrows a retained service; it never owns deletion.
		result.cleanup = invocationCleanup(nil, result.expiresAt, options.ShutdownDeadline)
		return result, nil
	}
	native, err := publisheridentity.NewDeploymentAllocator(control, authority, credential.Approval, key, selection.Name)
	if err != nil {
		return result, err
	}
	options.Publisher, options.State, options.ControlURL = native, result.profile, credential.ControlURL
	options.ExpiresAt = new(result.expiresAt)
	prepared, err := publisheradhoc.Prepare(ctx, options)
	if prepared != nil {
		result.cleanup = invocationCleanup(prepared.Cleanup, result.expiresAt, options.ShutdownDeadline)
	}
	if err == nil {
		result.native, result.service, result.config = prepared.Publisher(), prepared.Service, prepared.Config
		result.config.BrowserLoginAvailable = &browserLoginAvailable
	}
	return result, err
}
