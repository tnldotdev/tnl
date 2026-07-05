package tnldruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func (d *daemon) shutdown(timeout time.Duration) error {
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), timeout)
	defer cancelDrain()
	var result error
	deadline := time.Now().Add(timeout)
	for _, runtime := range d.ingresses {
		if runtime.controller != nil && runtime.controller.Ready(time.Now()) {
			result = errors.Join(result, runtime.controller.Drain(drainCtx, deadline))
		}
		if runtime.server != nil {
			result = errors.Join(result, runtime.server.Drain(drainCtx))
		}
		if runtime.usage != nil {
			result = errors.Join(result, runtime.usage.Close(drainCtx))
		}
		if runtime.recovery != nil {
			result = errors.Join(result, runtime.recovery.Close(drainCtx))
		}
	}
	for _, runtime := range d.relays {
		if runtime.controller != nil && runtime.controller.Ready(time.Now()) {
			result = errors.Join(result, runtime.controller.Drain(drainCtx, deadline))
		}
		for _, listener := range []net.Listener{runtime.tcpListener, runtime.internalListener} {
			if listener != nil {
				if err := closeNetworkListener(listener); err != nil {
					result = errors.Join(result, fmt.Errorf("close relay listener: %w", err))
				}
			}
		}
		if runtime.udpListener != nil {
			if err := closeNetworkListener(runtime.udpListener); err != nil {
				result = errors.Join(result, fmt.Errorf("close relay QUIC listener: %w", err))
			}
		}
		if runtime.registry != nil {
			err := runtime.registry.Drain(drainCtx)
			if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) &&
				!errors.Is(err, net.ErrClosed) {
				result = errors.Join(result, fmt.Errorf("drain relay publisher connections: %w", err))
			}
		}
	}
	if d.cancel != nil {
		d.cancel()
	}
	for _, runtime := range d.ingresses {
		if runtime.forwarder != nil {
			result = errors.Join(result, runtime.forwarder.Close())
		}
	}
	for _, runtime := range d.relays {
		if runtime.registry != nil {
			if err := runtime.registry.Close(); err != nil {
				result = errors.Join(result, fmt.Errorf("close relay publisher connections: %w", err))
			}
		}
	}
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 6*time.Second)
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
	forwardedDone := make(chan struct{})
	go func() {
		d.forwarded.Wait()
		close(forwardedDone)
	}()
	select {
	case <-forwardedDone:
	case <-cleanupCtx.Done():
		result = errors.Join(result, fmt.Errorf("wait for process components: %w", cleanupCtx.Err()))
	}
	if d.database != nil {
		d.database.Close()
	}
	return result
}

func closeNetworkListener(listener io.Closer) error {
	err := listener.Close()
	if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}
