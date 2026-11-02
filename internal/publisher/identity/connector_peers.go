package identity

import (
	"context"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type connectorPeerControl interface {
	DeliverConnectorPeerPair(context.Context, string, string, string, int64, credentials.ServiceRunToken) (controlv1.ConnectorPeerPairDelivery, error)
	ListConnectorPeerPairs(context.Context, string, string, string, credentials.ServiceRunToken) (controlv1.ConnectorPeerPairCandidates, error)
	ConfirmConnectorPeerPairPrepared(context.Context, string, string, string, controlv1.ConnectorPeerPairPrepared, credentials.ServiceRunToken) error
	ReportServiceRunObservations(context.Context, string, string, int64, credentials.ServiceRunToken, serviceaudit.Batch) error
}

func (n *Native) connectorPeerControl(service string) (connectorPeerControl, error) {
	if _, err := n.serviceControl(service); err != nil {
		return nil, err
	}
	control, ok := n.NativeControl.(connectorPeerControl)
	if !ok {
		return nil, ErrScope
	}
	return control, nil
}

func (n *Native) DeliverConnectorPeerPair(ctx context.Context, service, run, pair string, generation int64, token credentials.ServiceRunToken) (controlv1.ConnectorPeerPairDelivery, error) {
	control, err := n.connectorPeerControl(service)
	if err != nil {
		return controlv1.ConnectorPeerPairDelivery{}, err
	}
	return control.DeliverConnectorPeerPair(ctx, service, run, pair, generation, token)
}

func (n *Native) ListConnectorPeerPairs(ctx context.Context, service, run, after string, token credentials.ServiceRunToken) (controlv1.ConnectorPeerPairCandidates, error) {
	control, err := n.connectorPeerControl(service)
	if err != nil {
		return controlv1.ConnectorPeerPairCandidates{}, err
	}
	return control.ListConnectorPeerPairs(ctx, service, run, after, token)
}

func (n *Native) ConfirmConnectorPeerPairPrepared(ctx context.Context, service, run, pair string, body controlv1.ConnectorPeerPairPrepared, token credentials.ServiceRunToken) error {
	control, err := n.connectorPeerControl(service)
	if err != nil {
		return err
	}
	return control.ConfirmConnectorPeerPairPrepared(ctx, service, run, pair, body, token)
}

func (n *Native) ReportServiceRunObservations(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken, batch serviceaudit.Batch) error {
	control, err := n.connectorPeerControl(service)
	if err != nil {
		return err
	}
	return control.ReportServiceRunObservations(ctx, service, run, number, token, batch)
}
