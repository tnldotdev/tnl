package tnldruntime

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceaudit"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type ingressServiceObservationClient interface {
	IngestServiceObservations(context.Context, controlstate.IngressLeaseIdentity, serviceaudit.Batch) (controlstate.ServiceObservationResult, error)
}

// one instance belongs to one logical ingress. binding happens before its lease
// is exposed; retries retain this tuple even after renewals or lease loss.
type ingressServiceAudit struct {
	mu      sync.Mutex
	ctx     context.Context
	client  ingressServiceObservationClient
	metrics *observability.Metrics
	lease   controlstate.IngressLeaseIdentity
	queue   *serviceaudit.Queue
	closed  bool
	dropped uint64
}

func (a *ingressServiceAudit) bind(lease ingressv1.IngressLease) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	identity := controlstate.IngressLeaseIdentity{IngressID: lease.IngressId, IngressRunID: lease.IngressRunId, IngressLeaseRevision: uint64(lease.IngressLeaseRevision)}
	if a.closed {
		return serviceaudit.ErrRejected
	}
	if a.queue != nil {
		if a.lease != identity {
			return ingress.ErrIngressLeaseLost
		}
		return nil
	}
	q, err := serviceaudit.NewQueue(a.ctx, serviceaudit.QueueConfig{Metrics: a.metrics, Dropped: reportIngressAuditDrops, Report: func(ctx context.Context, batch serviceaudit.Batch) error {
		result, err := a.client.IngestServiceObservations(ctx, identity, batch)
		if errors.Is(err, controlstate.ErrIngressLeaseStale) || errors.Is(err, controlstate.ErrServiceAuditAccess) || errors.Is(err, serviceaudit.ErrInvalid) {
			return serviceaudit.ErrRejected
		}
		if err != nil {
			return err
		}
		return serviceaudit.ValidateAcknowledgement(result.Accepted, result.Duplicates, len(batch.Events))
	}})
	if err != nil {
		return err
	}
	a.lease, a.queue = identity, q
	return nil
}

func reportIngressAuditDrops(count uint64) {
	log.Printf("service audit observations dropped source=ingress count=%d", count)
}

func (a *ingressServiceAudit) Observe(event serviceaudit.Observation) bool {
	a.mu.Lock()
	if a.closed || a.queue == nil {
		a.dropped++
		a.mu.Unlock()
		a.metrics.ServiceAuditCount("dropped", 1)
		return false
	}
	q := a.queue
	a.mu.Unlock()
	return q.Observe(event)
}

func (a *ingressServiceAudit) Close(ctx context.Context) error {
	a.mu.Lock()
	a.closed = true
	q, dropped := a.queue, a.dropped
	a.dropped = 0
	a.mu.Unlock()
	if dropped > 0 {
		reportIngressAuditDrops(dropped)
	}
	if q != nil {
		return q.Close(ctx)
	}
	return nil
}

// the generated client and the existing private transport retain normal cluster
// authentication, private address dialing and TLS trust. errors omit peer data.
func (c *ingressRuntimeClient) IngestServiceObservations(ctx context.Context, lease controlstate.IngressLeaseIdentity, batch serviceaudit.Batch) (controlstate.ServiceObservationResult, error) {
	events, err := serviceaudit.APIObservations(batch)
	if err != nil {
		return controlstate.ServiceObservationResult{}, err
	}
	response, err := c.generated.ReportIngressServiceObservationsWithResponse(ctx, lease.IngressID, &ingressv1.ReportIngressServiceObservationsParams{IngressRunId: lease.IngressRunID, IngressLeaseRevision: int64(lease.IngressLeaseRevision)}, ingressv1.ReportIngressServiceObservationsJSONRequestBody{Events: events})
	if err != nil {
		return controlstate.ServiceObservationResult{}, errors.New("ingress service audit report failed")
	}
	if response != nil {
		if response.StatusCode() == http.StatusOK && response.JSON200 != nil {
			return controlstate.ServiceObservationResult{Accepted: response.JSON200.Accepted, Duplicates: response.JSON200.Duplicates}, nil
		}
		switch response.StatusCode() {
		case 400, 401, 403, 404, 409, 410, 413:
			return controlstate.ServiceObservationResult{}, serviceaudit.ErrRejected
		}
	}
	return controlstate.ServiceObservationResult{}, errors.New("ingress service audit batch was not accepted")
}

type serviceAuditCleanupStore interface {
	CleanupServiceAudit(context.Context, time.Time, int) (int64, error)
}

func runServiceAuditCleanup(ctx context.Context, store serviceAuditCleanupStore) error {
	return runBatchCleanup(ctx, time.Minute, func(ctx context.Context, now time.Time) (int, error) {
		count, err := store.CleanupServiceAudit(ctx, now, 1000)
		return int(count), err
	}, func(_ int, err error) {
		if err != nil && ctx.Err() == nil {
			logOperationalError("clean up service audit", failure.ServerWorkerFailed, err)
		}
	})
}
