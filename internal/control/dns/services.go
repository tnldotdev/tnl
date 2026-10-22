package dns

import (
	"context"
	"errors"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
)

type serviceEndpointStore interface {
	ClaimServiceEndpointDNSWork(context.Context, string, time.Time, time.Duration) (controlstate.ServiceEndpointDNSWork, bool, error)
	SaveServiceEndpointDNSWork(context.Context, controlstate.ServiceEndpointDNSWork, time.Time) (controlstate.ServiceEndpointDNSWork, error)
	ValidateServiceEndpointDNSWork(context.Context, controlstate.ServiceEndpointDNSWork, time.Time) error
	WithDNSRecordLock(context.Context, string, func() error) error
}

func (w *Worker) processServiceEndpoint(ctx context.Context, now time.Time) (_ bool, retErr error) {
	store, ok := w.store.(serviceEndpointStore)
	if !ok {
		return false, nil
	}
	ctx, finish := observability.WorkerAttempt(ctx, "dns.service.attempt")
	var attemptErr error
	defer func() { finishDNSAttempt(ctx, finish, errors.Join(retErr, attemptErr)) }()
	started := time.Now()
	work, found, err := store.ClaimServiceEndpointDNSWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if ctx.Err() == nil {
		observeDNS(ctx, w.config.Observer, "service", "claim", started, found, err)
	}
	if err != nil || !found {
		return found, err
	}
	err = store.WithDNSRecordLock(ctx, work.Hostname, func() error {
		if err := store.ValidateServiceEndpointDNSWork(ctx, work, w.now()); err != nil {
			return err
		}
		var saveErr error
		attemptErr, saveErr = w.advanceServiceEndpoint(ctx, store, work)
		return saveErr
	})
	if errors.Is(err, controlstate.ErrDNSPublicURLWorkStale) {
		return true, nil
	}
	return true, err
}

func (w *Worker) advanceServiceEndpoint(ctx context.Context, store serviceEndpointStore, work controlstate.ServiceEndpointDNSWork) (attemptErr, saveErr error) {
	started, initial := time.Now(), work.State
	work.LastError = ""
	record := AddressRecord{Owner: ServiceOwner(work.OwnerID), DomainID: work.DomainID, CanonicalHostname: work.Hostname, AuthorityReference: work.AuthorityReference, IngressIPv4Addresses: []string{"127.0.0.1"}}
	ready := true
	var err error
	if work.Public && work.State != controlstate.PublicURLDNSRemoving {
		record.IngressIPv4Addresses, record.IngressIPv6Addresses, ready, err = w.ingressAddresses(ctx, work.PoolID)
		ready = ready && len(record.IngressIPv4Addresses)+len(record.IngressIPv6Addresses) > 0
	}
	var nameservers []string
	if err == nil && ready {
		record, nameservers, ready, err = w.addressZoneRecord(ctx, record)
	}
	if err == nil && ready {
		removing := work.State == controlstate.PublicURLDNSRemoving
		ready, err = w.reconcileAddress(ctx, record, nameservers, removing, "service")
		if err == nil && ready {
			work.State = controlstate.PublicURLDNSPublished
			if removing {
				work.State = controlstate.PublicURLDNSRemoved
			}
			work.AvailableAt = time.Time{}
		}
	}
	if ctx.Err() != nil {
		return err, context.Cause(ctx)
	}
	observeDNS(ctx, w.config.Observer, "service", "advance", started, ready, err)
	if err != nil {
		work.LastError = storedFailureReason(err)
		work.AvailableAt = w.retryAvailableAt(uint64(work.Attempts), w.now())
		var terminal *terminalError
		if errors.As(err, &terminal) {
			work.State, work.AvailableAt = controlstate.PublicURLDNSFailed, time.Time{}
		}
	} else if !ready {
		work.AvailableAt = w.now().Add(w.config.PollInterval)
	}
	started = time.Now()
	attemptErr = err
	saved, err := store.SaveServiceEndpointDNSWork(ctx, work, w.now())
	if ctx.Err() == nil {
		observeDNS(ctx, w.config.Observer, "service", "save", started, true, err)
	}
	if err == nil && w.config.Observer != nil && saved.State != initial {
		w.config.Observer.ObserveDNSTransition("service", string(saved.State))
	}
	return attemptErr, err
}
