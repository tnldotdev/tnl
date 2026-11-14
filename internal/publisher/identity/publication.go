package identity

import (
	"context"
	"crypto/ed25519"
	"strings"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type DeploymentPublicationControl interface {
	PublicURLControl
	DeploymentPublication(context.Context, string, string, string, string, string) (controlv1.DeploymentPublication, error)
	AllocateDeploymentPublication(context.Context, string, string, string, string, controlv1.AllocateEphemeralPublicURLRequest) (controlv1.PublicURL, error)
}

// prepare narrows the signing adapter to one control-selected URL. it issues no
// grant: run creation, renewal, and deletion check the deployment credential.
func PrepareDeployment(ctx context.Context, control DeploymentPublicationControl, authority AssertionExchanger, approval controlv1.DeploymentCredential, private ed25519.PrivateKey, deployment, service string, allocation *controlv1.AllocateEphemeralPublicURLRequest) (*Native, *controlv1.DeploymentPublication, error) {
	if control == nil || authority == nil || !validSigningKey(private) || deployment == "" || (service == "") != (allocation != nil) {
		return nil, nil, ErrScope
	}
	token, err := authority.ExchangePublisherAssertion(ctx, approval.ClientId, approval.GrantId, approval.KeyId, private)
	if err != nil {
		return nil, nil, err
	}
	var u controlv1.PublicURL
	var limits *controlv1.ProjectPublicLimits
	if allocation == nil {
		publication, err := control.DeploymentPublication(ctx, token, approval.TeamId, approval.ProjectKey, deployment, service)
		if err != nil {
			return nil, nil, err
		}
		u, limits = publication.PublicUrl, publication.Limits
		if u.Ephemeral {
			return nil, nil, ErrScope
		}
	} else {
		u, err = control.AllocateDeploymentPublication(ctx, token, approval.TeamId, approval.ProjectKey, deployment, *allocation)
		if err != nil {
			return nil, nil, err
		}
		if !u.Ephemeral || u.Target != allocation.Target {
			return nil, nil, ErrScope
		}
	}
	i := authorityv1.PublisherEnrollmentResult{ClientId: approval.ClientId, KeyId: approval.KeyId, GrantId: approval.GrantId, TeamId: approval.TeamId, Kind: authorityv1.SavedPublicUrl, PublicUrlId: &u.Id}
	if allocation != nil {
		_, namespace, ok := strings.Cut(u.CanonicalHostname, ".")
		if !ok {
			return nil, nil, ErrScope
		}
		i.Kind, i.PublicUrlId, i.DomainId, i.Namespace = authorityv1.Namespace, nil, &u.DomainId, &namespace
	}
	native, err := NewNative(NativeControl{PublicURLControl: control}, authority, i, private)
	if err != nil {
		return nil, nil, err
	}
	if err := native.SelectPublicURL(u); err != nil {
		return nil, nil, err
	}
	return native, &controlv1.DeploymentPublication{PublicUrl: clonePublicURL(u), Limits: limits}, nil
}
