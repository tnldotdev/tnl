package dnscontroller

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

type managedEndpointStore interface {
	ClaimManagedEndpointDNSWork(context.Context, string, time.Time, time.Duration) (controlstate.ManagedEndpointDNSWork, bool, error)
	SaveManagedEndpointDNSWork(context.Context, controlstate.ManagedEndpointDNSWork, time.Time) (controlstate.ManagedEndpointDNSWork, error)
	ValidateManagedEndpointDNSWork(context.Context, controlstate.ManagedEndpointDNSWork, time.Time) error
	WithDNSRecordLock(context.Context, string, func() error) error
}

func (w *Worker) processManagedEndpoint(ctx context.Context, now time.Time) (bool, error) {
	store, ok := w.store.(managedEndpointStore)
	if !ok {
		return false, nil
	}
	work, found, err := store.ClaimManagedEndpointDNSWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if err != nil || !found {
		return found, err
	}
	err = store.WithDNSRecordLock(ctx, work.Hostname, func() error {
		if err := store.ValidateManagedEndpointDNSWork(ctx, work, w.now()); err != nil {
			return err
		}
		return w.advanceManagedEndpoint(ctx, store, work)
	})
	if errors.Is(err, controlstate.ErrDNSPublicURLWorkStale) {
		return true, nil
	}
	return true, err
}

func (w *Worker) advanceManagedEndpoint(ctx context.Context, store managedEndpointStore, work controlstate.ManagedEndpointDNSWork) error {
	record := AddressRecord{Owner: ManagedServiceOwner(work.OwnerID), DomainID: work.DomainID, CanonicalHostname: work.Hostname, AuthorityReference: work.AuthorityReference, IngressIPv4Addresses: []string{"127.0.0.1"}}
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
		ready, err = w.reconcileAddress(ctx, record, nameservers, removing, "managed_service")
		if err == nil && ready {
			work.State = controlstate.PublicURLDNSPublished
			if removing {
				work.State = controlstate.PublicURLDNSRemoved
			}
			work.AvailableAt = time.Time{}
		}
	}
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
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
	_, err = store.SaveManagedEndpointDNSWork(ctx, work, w.now())
	return err
}
