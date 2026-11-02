package stream

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type workloadControl struct {
	client  *workload.Client
	subject tunnelv1.VisitorSubject
}

// NewWorkloadControl borrows the exchanged workload's in-memory key. the caller
// owns workload renewal/revocation; every connection prepares an independent pair.
func NewWorkloadControl(client *workload.Client) (Control, error) {
	if client == nil {
		return nil, ErrServiceConnection
	}
	subject, err := client.Subject()
	if err != nil {
		return nil, err
	}
	c := &workloadControl{client, subject}
	return NewControlWithConfig(ControlConfig{Signer: c.signer, Resolve: c.resolve, Pair: client.PrepareConnectorPeerPair, Permission: client.VisitorPermission, Close: func() error { return nil }})
}
func (c *workloadControl) signer(_ context.Context, identity string) (Signer, error) {
	s, err := c.client.Subject()
	if err != nil {
		return Signer{}, err
	}
	if identity != "" || s != c.subject {
		return Signer{}, ErrServiceConnection
	}
	return Signer{Subject: s, PublicKey: c.client.PublicKey(), Sign: c.client.Sign}, nil
}
func (c *workloadControl) resolve(ctx context.Context, service string) (Run, error) {
	r, err := c.client.SelectServiceRun(ctx, service)
	if err != nil {
		return Run{}, err
	}
	if r.ServiceId != service || !visitorsubject.Equal(r.Subject, c.subject) || !opaqueid.Valid(r.ServiceRunId, opaqueid.ServiceRunPrefix) || r.RunNumber < 1 || r.TrustRevision < 1 || !validProtocol(string(r.Protocol)) || !r.ExpiresAt.After(time.Now()) || r.Endpoint == nil {
		return Run{}, ErrServiceConnection
	}
	return Run{ServiceID: service, ServiceRunID: r.ServiceRunId, RunNumber: uint64(r.RunNumber), ValidUntil: r.ExpiresAt, Protocol: string(r.Protocol), TrustRevision: r.TrustRevision, Endpoint: r.Endpoint, PairReady: r.PairReady}, nil
}
