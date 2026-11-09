package local

import (
	"context"
	"errors"
	"net"
	"strconv"

	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// service grants start service runs through the existing invocation operation.
// they never realize a service, allocate a public URL, or change saved policy.
func (a *appRuntime) prepareApplicationService(ctx context.Context, request publisherprotocol.Invocation, bound bool, profile *clientstate.Store, native *publisheridentity.Native, identity authorityv1.PublisherEnrollmentResult) (_ publisherprotocol.Registration, result error) {
	if request.AccessMode != nil || request.Ip != nil || request.Limits != nil || request.RequirePostQuantum != nil {
		return publisherprotocol.Registration{}, credentialfile.ErrGrant
	}
	saved, err := native.SavedService(ctx)
	if err != nil {
		return publisherprotocol.Registration{}, applicationAuthorityError(err)
	}
	if saved.Protocol != controlv1.ServiceProtocolHTTP {
		return publisherprotocol.Registration{}, credentialfile.ErrGrant
	}
	if saved.Endpoint == nil || saved.Endpoint.Port < 1 || saved.Endpoint.Port > 65535 {
		return publisherprotocol.Registration{}, credentialfile.ErrApplication
	}
	hostname, err := naming.CanonicalizeHostname(saved.Endpoint.Hostname)
	if err != nil || hostname != saved.Endpoint.Hostname {
		return publisherprotocol.Registration{}, credentialfile.ErrApplication
	}
	trust, err := publisheridentity.ServiceTrust(saved)
	if err != nil {
		return publisherprotocol.Registration{}, applicationAuthorityError(err)
	}
	publicURL := ""
	if saved.Endpoint.Public {
		publicURL = "https://" + hostname
		if saved.Endpoint.Port != 443 {
			publicURL = "https://" + net.JoinHostPort(hostname, strconv.Itoa(saved.Endpoint.Port))
		}
	}
	if err := a.manager.AddService(publisherapp.Service{Name: request.InvocationId, Directory: ".", ServiceProtocol: "http", Readiness: publisherapp.Readiness{Path: "/"}}); err != nil {
		return publisherprotocol.Registration{}, err
	}
	id, err := a.manager.Reserve(request.InvocationId, request.Owner, request.Pid, publicURL)
	if err != nil {
		return publisherprotocol.Registration{}, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, a.manager.Unregister(id, request.Owner))
			a.mu.Lock()
			delete(a.prepared, id)
			a.mu.Unlock()
		}
	}()
	options := &invocation.ServicePublicationOptions{Manager: a.manager, State: profile, Native: native, Identity: identity, Saved: saved, Plan: targetplan.TargetPlan{Protocol: config.ProtocolHTTP, Trust: trust}}
	a.mu.Lock()
	a.prepared[id] = appPreparation{invocation: &request, preparedPublication: !bound, servicePublication: options}
	a.mu.Unlock()
	if bound {
		if err := a.manager.RegisterContext(ctx, id, request.Owner, request.Target, ""); err != nil {
			return publisherprotocol.Registration{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return publisherprotocol.Registration{}, err
	}
	return publisherprotocol.Registration{Version: 1, RegistrationID: id, Owner: request.Owner, Target: request.Target}, nil
}
