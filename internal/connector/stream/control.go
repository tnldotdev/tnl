package stream

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type controlAdapter struct {
	client     *clientcontrol.Client
	profile    *clientstate.Store
	identityID string
	deviceMu   sync.Mutex
}

func (*controlAdapter) String() string   { return "private connector control" }
func (*controlAdapter) GoString() string { return "private connector control" }

// NewControl borrows the signed-in identity's protected, server-scoped device.
// each native connection creates its own signed owner key at preparation.
func NewControl(client *clientcontrol.Client, profile *clientstate.Store, identityID string) (Control, error) {
	if client == nil || profile == nil || !opaqueid.Valid(identityID, opaqueid.IdentityPrefix) {
		return nil, ErrServiceConnection
	}
	return &controlAdapter{client: client, profile: profile, identityID: identityID}, nil
}

func (c *controlAdapter) ConnectorSigner(ctx context.Context, identity string) (Signer, error) {
	if identity != c.identityID {
		return Signer{}, ErrServiceConnection
	}
	c.deviceMu.Lock()
	defer c.deviceMu.Unlock()
	device, err := c.profile.EnsureEnrolledVisitorDevice(ctx, identity, c.client.EnrollVisitorDevice)
	if err != nil {
		if errors.Is(err, clientstate.ErrPublisherStateConflict) {
			return Signer{}, errors.Join(ErrServiceConnection, err)
		}
		return Signer{}, err
	}
	return Signer{Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: identity, DeviceID: device.ID}, PublicKey: device.SigningKey.Public().(ed25519.PublicKey), Sign: func(message []byte) []byte { return ed25519.Sign(device.SigningKey, message) }}, nil
}

func (c *controlAdapter) ResolveService(ctx context.Context, service string) (Run, error) {
	if !opaqueid.Valid(service, opaqueid.ServicePrefix) {
		return Run{}, ErrServiceConnection
	}
	signer, err := c.ConnectorSigner(ctx, c.identityID)
	if err != nil {
		return Run{}, err
	}
	selected, err := c.client.SelectServiceRun(ctx, service, signer.Subject.DeviceID)
	if err != nil {
		return Run{}, err
	}
	if selected.Endpoint == nil || selected.ServiceId != service || !visitorsubject.Equal(selected.Subject, signer.Subject) || !opaqueid.Valid(selected.ServiceRunId, opaqueid.ServiceRunPrefix) || selected.RunNumber < 1 || selected.TrustRevision < 1 || !selected.ExpiresAt.After(time.Now()) || !validProtocol(string(selected.Protocol)) {
		return Run{}, ErrServiceConnection
	}
	return Run{ServiceID: service, ServiceRunID: selected.ServiceRunId, RunNumber: uint64(selected.RunNumber), ValidUntil: selected.ExpiresAt, Protocol: string(selected.Protocol), TrustRevision: selected.TrustRevision, Endpoint: selected.Endpoint, PairReady: selected.PairReady}, nil
}

func (c *controlAdapter) PrepareNativePeerPair(ctx context.Context, service string, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
	device, err := c.ConnectorSigner(ctx, c.identityID)
	if err != nil {
		return controlv1.NativePeerPair{}, err
	}
	if !visitorsubject.Equal(body.Subject, device.Subject) {
		return controlv1.NativePeerPair{}, ErrServiceConnection
	}
	if body.Action == "renew" && body.PreviousPairId != nil {
		return c.client.RenewDeviceNativePeerPair(ctx, service, *body.PreviousPairId, device.Subject.DeviceID, body)
	}
	return c.client.PrepareDeviceNativePeerPair(ctx, service, device.Subject.DeviceID, body)
}

func (c *controlAdapter) VisitorPermission(ctx context.Context, service string) (controlv1.VisitorTokenResponse, error) {
	device, err := c.ConnectorSigner(ctx, c.identityID)
	if err != nil {
		return controlv1.VisitorTokenResponse{}, err
	}
	source, err := json.Marshal(controlv1.VisitorTokenDeviceSource{Kind: controlv1.VisitorTokenDevice, DeviceId: device.Subject.DeviceID})
	if err != nil {
		return controlv1.VisitorTokenResponse{}, err
	}
	return c.client.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service}, Source: source})
}

// control has no per-ingress reservations. the connection joins its packet and
// application work; unrenewed control authority expires at its original bound.
func (*controlAdapter) Close() error                       { return nil }
func (*controlAdapter) CloseContext(context.Context) error { return nil }
