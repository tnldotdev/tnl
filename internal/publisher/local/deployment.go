package local

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// deployment authority never selects local configuration or a publisher file.
// the existing invocation manager owns the worker and its exact allocation.
func (a *appRuntime) prepareDeploymentInvocation(ctx context.Context, r publisherprotocol.Invocation) (*publisheridentity.Native, *clientstate.Store, controlv1.PublicURL, applicationlimits.Limits, error) {
	var zero controlv1.PublicURL
	var limits applicationlimits.Limits
	selection := r.Deployment
	if selection == nil || r.ServerUrl != nil || r.PublisherCredentialFile != "" || r.PublisherIdentityId != "" || selection.Service != "" && (r.AccessMode != nil || r.Ip != nil || r.Limits != nil || r.RequirePostQuantum != nil) {
		return nil, nil, zero, limits, publisheridentity.ErrScope
	}
	credential, err := auth.ParseDeploymentCredential(selection.Credential)
	if err != nil {
		return nil, nil, zero, limits, err
	}
	if err := credential.SelectProject(selection.Project); err != nil {
		return nil, nil, zero, limits, err
	}
	profile, err := a.state.Server(ctx, credential.ControlURL)
	if err != nil {
		return nil, nil, zero, limits, err
	}
	control, err := clientcontrol.New(credential.ControlURL, nil, "")
	if err != nil {
		return nil, nil, zero, limits, err
	}
	authority, err := clientauthority.New(credential.ControlURL, nil, "")
	if err != nil {
		return nil, nil, zero, limits, err
	}
	private, err := base64.RawURLEncoding.DecodeString(credential.PrivateKey)
	if err != nil {
		return nil, nil, zero, limits, auth.ErrDeploymentCredential
	}
	var allocation *controlv1.AllocateEphemeralPublicURLRequest
	if selection.Service == "" {
		allocation = &controlv1.AllocateEphemeralPublicURLRequest{InvocationId: r.InvocationId, Target: r.Target, RequirePostQuantum: r.RequirePostQuantum, Ip: r.Ip, Limits: r.Limits}
		if r.AccessMode != nil {
			allocation.AccessMode = new(controlv1.VisitorAccessMode(*r.AccessMode))
		}
	}
	native, publication, err := publisheridentity.PrepareDeployment(ctx, control, authority, credential.Approval, ed25519.PrivateKey(private), selection.Name, selection.Service, allocation)
	if err != nil {
		return nil, nil, zero, limits, err
	}
	if allocation != nil {
		limits, err = invocationLimits(r.Limits)
	} else {
		var settings *config.Limits
		if publication.Limits != nil {
			data, marshalErr := json.Marshal(publication.Limits)
			if marshalErr != nil {
				return native, profile, publication.PublicUrl, limits, marshalErr
			}
			if err = json.Unmarshal(data, &settings); err != nil {
				return native, profile, publication.PublicUrl, limits, err
			}
		}
		limits, err = config.ResolveWorkLimits(settings, "http")
		if err == nil {
			traffic, trafficErr := config.ResolveTrafficSelection(settings)
			err = trafficErr
			if err == nil {
				native, err = native.WithTraffic(traffic)
			}
		}
	}
	return native, profile, publication.PublicUrl, limits, err
}
