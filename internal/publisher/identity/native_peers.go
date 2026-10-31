package identity

import (
	"context"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type nativePeerControl interface {
	DeliverNativePeerPair(context.Context, string, string, string, int64, credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error)
	ListNativePeerPairs(context.Context, string, string, string, credentials.ServiceRunToken) (controlv1.NativePeerPairCandidates, error)
	ConfirmNativePeerPairPrepared(context.Context, string, string, string, controlv1.NativePeerPairPrepared, credentials.ServiceRunToken) error
	ReportServiceRunObservations(context.Context, string, string, int64, credentials.ServiceRunToken, serviceaudit.Batch) error
}

func (n *Native) nativePeerControl(service string) (nativePeerControl, error) {
	if _, err := n.serviceControl(service); err != nil {
		return nil, err
	}
	control, ok := n.NativeControl.(nativePeerControl)
	if !ok {
		return nil, ErrScope
	}
	return control, nil
}

func (n *Native) DeliverNativePeerPair(ctx context.Context, service, run, pair string, generation int64, token credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error) {
	control, err := n.nativePeerControl(service)
	if err != nil {
		return controlv1.NativePeerPairDelivery{}, err
	}
	return control.DeliverNativePeerPair(ctx, service, run, pair, generation, token)
}

func (n *Native) ListNativePeerPairs(ctx context.Context, service, run, after string, token credentials.ServiceRunToken) (controlv1.NativePeerPairCandidates, error) {
	control, err := n.nativePeerControl(service)
	if err != nil {
		return controlv1.NativePeerPairCandidates{}, err
	}
	return control.ListNativePeerPairs(ctx, service, run, after, token)
}

func (n *Native) ConfirmNativePeerPairPrepared(ctx context.Context, service, run, pair string, body controlv1.NativePeerPairPrepared, token credentials.ServiceRunToken) error {
	control, err := n.nativePeerControl(service)
	if err != nil {
		return err
	}
	return control.ConfirmNativePeerPairPrepared(ctx, service, run, pair, body, token)
}

func (n *Native) ReportServiceRunObservations(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken, batch serviceaudit.Batch) error {
	control, err := n.nativePeerControl(service)
	if err != nil {
		return err
	}
	return control.ReportServiceRunObservations(ctx, service, run, number, token, batch)
}
