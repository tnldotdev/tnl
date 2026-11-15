package identity

import (
	"context"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type serviceAuditControl interface {
	ReportServiceRunObservations(context.Context, string, string, int64, credentials.ServiceRunToken, serviceaudit.Batch) error
}

func (n *Native) ReportServiceRunObservations(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken, batch serviceaudit.Batch) error {
	if _, err := n.serviceControl(service); err != nil {
		return err
	}
	if !opaqueid.Valid(run, opaqueid.ServiceRunPrefix) || number < 1 || token == "" || len(batch.Events) == 0 {
		return ErrScope
	}
	for _, e := range batch.Events {
		if e.ServiceKind != "service" || e.ServiceID != service || e.RunID != run || e.RunNumber != number {
			return ErrScope
		}
	}
	return n.Services.ReportServiceRunObservations(ctx, service, run, number, token, batch)
}
