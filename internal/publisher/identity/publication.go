package identity

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type DeploymentPublicationControl interface {
	ServiceControl
	DeploymentPublication(context.Context, string, string, string, string, string) (controlv1.Service, error)
}

// prepare selects one named service without enrolling another identity or
// replacing the registered credential's grant and key.
func PrepareDeployment(ctx context.Context, control DeploymentPublicationControl, authority AssertionExchanger, approval controlv1.DeploymentCredential, private ed25519.PrivateKey, deployment, service string) (*Native, *controlv1.Service, error) {
	if control == nil || authority == nil || !validSigningKey(private) || deployment == "" || service == "" ||
		!opaqueid.Valid(approval.ClientId, opaqueid.PublisherIdentityPrefix) ||
		!opaqueid.Valid(approval.GrantId, opaqueid.PublisherGrantPrefix) ||
		!opaqueid.Valid(approval.KeyId, opaqueid.PublisherIdentityKeyPrefix) ||
		approval.TeamId == "" || approval.ProjectKey == "" || !approval.ExpiresAt.After(time.Now()) {
		return nil, nil, ErrScope
	}
	native, err := newNative(NativeControl{Services: control}, authority, nativeScope{
		clientID: approval.ClientId, keyID: approval.KeyId, grantID: approval.GrantId,
		teamID: approval.TeamId, kind: "deployment_credential",
	}, private)
	if err != nil {
		return nil, nil, err
	}
	token, err := native.Access(ctx)
	if err != nil {
		return nil, nil, err
	}
	selected, err := control.DeploymentPublication(ctx, token, approval.TeamId, approval.ProjectKey, deployment, service)
	if err != nil {
		return nil, nil, err
	}
	if !opaqueid.Valid(selected.Id, opaqueid.ServicePrefix) || selected.TeamId != approval.TeamId ||
		!selected.Enabled || selected.Protocol != controlv1.ServiceProtocolHTTP || selected.ExpiresAt != nil && !selected.ExpiresAt.After(time.Now()) {
		return nil, nil, ErrScope
	}
	if _, err = ServiceTrust(selected); err != nil {
		return nil, nil, err
	}
	native.selectedServiceID = selected.Id
	return native, &selected, nil
}
