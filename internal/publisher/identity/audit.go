package identity

import (
	"context"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type publisherAuditControl interface {
	ReportPublisherServiceObservations(context.Context, string, uint64, credentials.PublishRunToken, serviceaudit.Batch) error
}

func (n *Native) ReportPublisherServiceObservations(ctx context.Context, runID string, number uint64, token credentials.PublishRunToken, batch serviceaudit.Batch) error {
	if n == nil || n.publicURL.Id == "" || len(batch.Events) == 0 {
		return ErrScope
	}
	for _, e := range batch.Events {
		if e.ServiceKind != "public_url" || e.ServiceID != n.publicURL.Id || e.RunID != runID {
			return ErrScope
		}
	}
	control, ok := n.NativeControl.(publisherAuditControl)
	if !ok {
		return serviceaudit.ErrRejected
	}
	return control.ReportPublisherServiceObservations(ctx, runID, number, token, batch)
}
