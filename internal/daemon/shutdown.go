package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func (d *daemon) shutdown(timeout time.Duration) error {
	d.draining.Store(true)
	started := time.Now()
	owner := d.ctx
	if owner == nil {
		owner = context.Background()
	}
	drainCtx, cancelDrain := context.WithTimeout(context.WithoutCancel(owner), timeout)
	defer cancelDrain()
	var result error
	deadline := time.Now().Add(timeout)
	for _, runtime := range d.ingresses {
		if runtime.private != nil {
			runtime.private.StopAccepting()
		}
	}
	// drain visitors before flushing recovery and service-audit observations.
	for _, runtime := range d.ingresses {
		if runtime.privateQUIC != nil {
			result = errors.Join(result, runtime.privateQUIC.StopAccepting())
		}
		if runtime.controller != nil && runtime.controller.Ready(time.Now()) {
			result = errors.Join(result, shutdownStep("ingress_lease", func() error { return runtime.controller.Drain(drainCtx, deadline) }))
		}
		if runtime.server != nil {
			result = errors.Join(result, shutdownStep("ingress_visitors", func() error { return runtime.server.Drain(drainCtx) }))
		}
		if runtime.private != nil {
			result = errors.Join(result, shutdownStep("private_ingress_streams", func() error { return runtime.private.Drain(drainCtx) }))
		}
		if runtime.recovery != nil {
			result = errors.Join(result, runtime.recovery.Close(drainCtx))
		}
		if runtime.audit != nil {
			result = errors.Join(result, shutdownStep("ingress_service_audit", func() error { return runtime.audit.Close(drainCtx) }))
		}
	}
	// relay publisher connections stay available until ingress stops forwarding.
	for _, runtime := range d.relays {
		if runtime.controller != nil && runtime.controller.Ready(time.Now()) {
			result = errors.Join(result, shutdownStep("relay_lease", func() error { return runtime.controller.Drain(drainCtx, deadline) }))
		}
		for _, listener := range []net.Listener{runtime.tcpListener, runtime.internalListener} {
			if listener != nil {
				if err := closeNetworkListener(listener); err != nil {
					result = errors.Join(result, fmt.Errorf("close relay listener: %w", err))
				}
			}
		}
		if runtime.udpListener != nil {
			if err := runtime.udpListener.StopAccepting(); err != nil {
				result = errors.Join(result, fmt.Errorf("close relay QUIC listener: %w", err))
			}
		}
		if runtime.registry != nil {
			err := shutdownStep("relay_connections", func() error { return runtime.registry.Drain(drainCtx) })
			if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) &&
				!errors.Is(err, net.ErrClosed) {
				result = errors.Join(result, fmt.Errorf("drain relay publisher connections: %w", err))
			}
		}
		if runtime.serviceRegistry != nil {
			result = errors.Join(result, shutdownStep("private_relay_connections", func() error { return runtime.serviceRegistry.Drain(drainCtx) }))
		}
	}
	// only cancel component contexts after the bounded drain has finished.
	if d.cancel != nil {
		d.cancel()
	}
	for _, runtime := range d.ingresses {
		if runtime.private != nil {
			result = errors.Join(result, runtime.private.Close())
		}
		if runtime.privateQUIC != nil {
			result = errors.Join(result, runtime.privateQUIC.Close())
		}
		if runtime.forwarder != nil {
			result = errors.Join(result, runtime.forwarder.Close())
		}
	}
	for _, runtime := range d.relays {
		if runtime.serviceRegistry != nil {
			result = errors.Join(result, runtime.serviceRegistry.Close())
		}
		if runtime.registry != nil {
			if err := runtime.registry.Close(); err != nil {
				result = errors.Join(result, fmt.Errorf("close relay publisher connections: %w", err))
			}
		}
		if runtime.udpListener != nil {
			if err := closeNetworkListener(runtime.udpListener); err != nil {
				result = errors.Join(result, fmt.Errorf("close relay QUIC transport: %w", err))
			}
		}
	}
	cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(owner), 6*time.Second)
	defer cancelCleanup()
	serverErrors := make(chan error, 3)
	servers := 0
	for _, server := range []struct {
		name   string
		server *http.Server
	}{
		{name: "control API", server: d.controlServer},
		{name: "private control API", server: d.privateControlServer},
	} {
		if server.server != nil {
			servers++
			go func() {
				err := server.server.Shutdown(cleanupCtx)
				if err != nil {
					err = fmt.Errorf("shut down %s: %w", server.name, errors.Join(err, server.server.Close()))
				}
				serverErrors <- err
			}()
		}
	}
	if d.metricsServer != nil {
		servers++
		go func() {
			err := d.metricsServer.Shutdown(cleanupCtx)
			if err != nil {
				err = fmt.Errorf("shut down observability: %w", err)
			}
			serverErrors <- err
		}()
	}
	for range servers {
		result = errors.Join(result, <-serverErrors)
	}
	for _, listener := range []net.Listener{d.controlListener, d.privateControlListener} {
		if listener != nil {
			if err := closeNetworkListener(listener); err != nil {
				result = errors.Join(result, fmt.Errorf("close control listener: %w", err))
			}
		}
	}
	componentsDone := make(chan struct{})
	go func() {
		d.components.Wait()
		close(componentsDone)
	}()
	select {
	case <-componentsDone:
	case <-cleanupCtx.Done():
		result = errors.Join(result, fmt.Errorf("wait for process components: %w", cleanupCtx.Err()))
	}
	if d.database != nil {
		d.database.Close()
	}
	log.Printf("tnld shutdown elapsed=%s outcome=%s", time.Since(started).Round(time.Millisecond), shutdownOutcome(result))
	return result
}

func shutdownStep(stage string, run func() error) error {
	started := time.Now()
	err := run()
	log.Printf("tnld shutdown stage=%s elapsed=%s outcome=%s", stage, time.Since(started).Round(time.Millisecond), shutdownOutcome(err))
	return err
}

func shutdownOutcome(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "error"
	}
}

func closeNetworkListener(listener io.Closer) error {
	err := listener.Close()
	if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}
