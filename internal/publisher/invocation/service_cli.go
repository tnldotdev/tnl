package invocation

import (
	"context"
	"errors"
	"sync"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	tunneltransport "github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const defaultProvisioningStalledDelay = 2 * time.Minute

// RunServiceCLI binds a prepared service operation to its caller-owned journal
// and presentation. run must join its work before returning. identity selection,
// allocation cleanup, process ownership, and journal finalization stay with their
// callers; this operation never enrolls or allocates another publication.
func RunServiceCLI(ctx context.Context, tunnel *clientstate.Tunnel, saved controlv1.Service, cfg publisherservice.RunConfig, output *Presentation, run func(context.Context, publisherservice.RunConfig) error) error {
	if tunnel == nil || run == nil || saved.Id == "" || saved.Id != cfg.ServiceID || saved.Protocol != cfg.Metadata.Protocol || saved.Endpoint == nil {
		return identity.ErrScope
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	address := ""
	if saved.Protocol == controlv1.ServiceProtocolHTTP && saved.Endpoint.Public {
		address = "https://" + saved.Endpoint.Hostname
	}
	var mu sync.Mutex
	var number uint64
	var ready bool
	var announced bool
	var fallback, draining bool
	var healthObserved, healthy bool
	var observationError error
	record := func(err error) error {
		if err != nil {
			observationError = errors.Join(observationError, err)
			cancel()
		}
		return err
	}
	// timer ownership is separate from callback serialization: stopping joins
	// a callback that may already hold mu, without holding mu while waiting.
	var timerMu sync.Mutex
	var stopTimer func()
	stopStall := func() {
		if stopTimer != nil {
			stopTimer()
			stopTimer = nil
		}
	}
	joinStall := func() {
		timerMu.Lock()
		defer timerMu.Unlock()
		stopStall()
	}
	defer joinStall()
	startStall := func(run uint64) {
		if output == nil || output.ProvisioningStalled == nil {
			return
		}
		life, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		timer := time.NewTimer(defaultProvisioningStalledDelay)
		go func() {
			defer close(done)
			defer timer.Stop()
			select {
			case <-life.Done():
				return
			case <-timer.C:
				mu.Lock()
				defer mu.Unlock()
				if life.Err() == nil && observationError == nil && number == run && !announced {
					record(output.provisioningStalled(run))
				}
			}
		}()
		stopTimer = func() { stop(); <-done }
	}
	prepared, onReady, status := cfg.Prepared, cfg.Ready, cfg.ObserveReadiness
	cfg.Prepared = func(preparation controlv1.ServiceRunPreparation) error {
		timerMu.Lock()
		defer timerMu.Unlock()
		mu.Lock()
		if preparation.ServiceId != saved.Id || preparation.RunNumber < 1 || uint64(preparation.RunNumber) <= number {
			mu.Unlock()
			return identity.ErrScope
		}
		mu.Unlock()
		stopStall()
		mu.Lock()
		defer mu.Unlock()
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		if prepared != nil {
			if err := prepared(preparation); err != nil {
				return record(err)
			}
		}
		number, ready, announced = uint64(preparation.RunNumber), false, false
		fallback, draining, healthObserved = false, false, false
		if err := tunnel.SetProvisioning(ctx, number); err != nil {
			return record(err)
		}
		if err := record(output.provisioning(address, number)); err != nil {
			return err
		}
		startStall(number)
		return nil
	}
	cfg.Ready = func() error {
		timerMu.Lock()
		defer timerMu.Unlock()
		stopStall()
		mu.Lock()
		defer mu.Unlock()
		if number == 0 || ctx.Err() != nil {
			return identity.ErrScope
		}
		if onReady != nil {
			if err := onReady(); err != nil {
				return record(err)
			}
		}
		if err := tunnel.SetReady(ctx, address, number); err != nil {
			return record(err)
		}
		ready, announced = true, true
		return record(output.ready(address, number))
	}
	cfg.ObserveReadiness = func(current publisherservice.RunStatus) {
		mu.Lock()
		defer mu.Unlock()
		if status != nil {
			status(current)
		}
		if number == 0 {
			return
		}
		if current.Draining {
			if !draining {
				draining = true
				until := time.Now().Add(10 * time.Second)
				if cfg.ShutdownDeadline != nil {
					until = cfg.ShutdownDeadline()
				}
				finish, stop := context.WithDeadline(context.WithoutCancel(ctx), until)
				err := tunnel.SetDraining(finish)
				stop()
				record(errors.Join(err, output.draining()))
			}
			return
		}
		if ctx.Err() != nil || observationError != nil || draining {
			return
		}
		if !fallback {
			for slot, transport := range current.Transports {
				if current.Connected[slot] && transport == tunneltransport.TransportTLSTCP {
					fallback = true
					if record(output.transportFallback(number, string(transport))) != nil {
						return
					}
					break
				}
			}
		}
		if !current.LastCheck.IsZero() && (!healthObserved || healthy != current.TargetHealthy) {
			healthObserved, healthy = true, current.TargetHealthy
			if !healthy && record(output.targetUnavailable()) != nil {
				return
			}
		}
		if !announced || ready == current.Ready {
			return
		}
		// the run owner announces the first ready transition through Ready.
		// subsequent observations update this same journal, not another run.
		if current.Ready {
			if record(tunnel.SetReady(ctx, address, number)) == nil {
				record(output.ready(address, number))
			}
		} else {
			if record(tunnel.SetProvisioning(ctx, number)) == nil {
				record(output.provisioning(address, number))
			}
		}
		ready = current.Ready
	}
	err := run(ctx, cfg)
	joinStall()
	mu.Lock()
	err = errors.Join(err, observationError, context.Cause(ctx))
	mu.Unlock()
	if err != nil && !(context.Cause(ctx) == context.Canceled && failure.Only(err, context.Canceled)) {
		return failure.Wrap("publish service", failure.TunnelUnavailable, err)
	}
	return output.stopped()
}
