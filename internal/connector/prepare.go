package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"

	"github.com/tnldotdev/tnl/internal/config"
	connectionruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	tcpconnect "github.com/tnldotdev/tnl/internal/connector/stream"
	workloadclient "github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// preparation is incremental and failure is local to the requested service.
// the exchanged service-ID snapshot is independent of this listener map.
func (b *nativeConnectionBackend) prepareService(ctx context.Context, name string, previous *preparedConnection, service controlv1.PrivateService, client *workloadclient.Client) (*preparedConnection, error) {
	if !slices.Contains(b.scope.Services, name) {
		return nil, connectionruntime.ErrUnavailable
	}
	if err := ValidateService(service); err != nil {
		return nil, err
	}
	if string(service.Protocol) != config.Protocol(b.project.Config.Services[name]) {
		return nil, connectionruntime.ErrInvalid
	}
	endpoint := service.ManagedTls
	b.mu.Lock()
	deadline := b.deadline
	b.mu.Unlock()
	connection := connectionruntime.Connection{Schema: 1, Protocol: string(service.Protocol), Host: "127.0.0.1", Port: endpoint.Port, ExpiresAt: deadline}
	transportID, err := opaqueid.New("ctg_")
	if err != nil {
		return nil, err
	}
	connection.TransportID = transportID
	p := &preparedConnection{service: service, connection: connection}
	if previous != nil {
		p.listener = previous.listener
		p.connection.Kubeconfig, p.connection.Context = previous.connection.Kubeconfig, previous.connection.Context
		p.kubeSource = previous.kubeSource
	}
	verification := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname}
	var control tcpconnect.Control
	// each new adapter receives a fresh transport ID even when its listener stays.
	identity := ""
	if client != nil {
		control, err = tcpconnect.NewWorkloadControl(client)
	} else {
		identity = b.human.identity.Identity.Id
		control, err = tcpconnect.NewControl(b.human.authenticated.Control, b.human.store, identity)
	}
	if err != nil {
		return nil, err
	}
	run, err := control.ResolvePrivateService(ctx, service.Id)
	if err != nil {
		if closer, ok := control.(io.Closer); ok {
			_ = closer.Close()
		}
		return nil, err
	}
	if run.Protocol != string(service.Protocol) || run.ManagedTLS == nil || *run.ManagedTLS != *endpoint {
		if closer, ok := control.(io.Closer); ok {
			_ = closer.Close()
		}
		return nil, connectionruntime.ErrUnavailable
	}
	if p.listener == nil {
		port := endpoint.Port
		// independently verified SDK identities cannot share a local capability
		// or compete for the same managed port. metadata retains the remote port.
		if b.parentPID > 0 {
			port = 0
		}
		base, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			if closer, ok := control.(io.Closer); ok {
				_ = closer.Close()
			}
			return nil, err
		}
		p.listener = connectionruntime.NewListenerSwitch(base)
	}
	b.mu.Lock()
	if b.closed || b.workload != client {
		b.mu.Unlock()
		if previous == nil {
			_ = p.listener.Close()
		}
		if closer, ok := control.(io.Closer); ok {
			_ = closer.Close()
		}
		return nil, connectionruntime.ErrUnprepared
	}
	if previous != nil && previous.cancel != nil {
		previous.cancel()
	}
	b.prepared[name] = p
	b.publishLocked()
	b.mu.Unlock()
	lifetime, cancel := context.WithCancel(b.lifetime)
	p.cancel = cancel
	prepared := false
	defer func() {
		if !prepared {
			cancel()
		}
	}()
	listener := p.listener.Next()
	ready := make(chan struct{})
	done := make(chan error, 1)
	connection.Port = listener.Addr().(*net.TCPAddr).Port
	configuration := tcpconnect.Config{Control: control, PrivateServiceID: service.Id, IdentityID: identity, Protocol: string(service.Protocol), TrustRevision: run.TrustRevision, ManagedTLS: endpoint, ServiceTLS: verification, CleanupContext: b.cleanup, Ready: func() error { close(ready); return nil }}
	b.workers.Go(func() {
		defer listener.Close()
		err := tcpconnect.Serve(lifetime, listener, configuration)
		b.mu.Lock()
		if b.prepared[name] == p {
			if b.lifetime.Err() == nil {
				p.err = errors.Join(connectionruntime.ErrUnavailable, err)
			} else if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				b.cleanupErr = errors.Join(b.cleanupErr, err)
			}
			b.publishLocked()
		}
		b.mu.Unlock()
		done <- err
	})
	select {
	case <-ready:
	case err := <-done:
		return nil, errors.Join(connectionruntime.ErrUnavailable, err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	connection.Kubeconfig, connection.Context = p.connection.Kubeconfig, p.connection.Context
	p.connection = connection
	p.control = control
	if client != nil {
		session, err := client.Session()
		if err != nil {
			return nil, err
		}
		p.sessionID = session.Id
	}
	if string(service.Protocol) == "http" || string(service.Protocol) == "kubernetes" {
		p.connection.URL = "https://" + net.JoinHostPort(endpoint.Hostname, strconv.Itoa(endpoint.Port))
	}
	if string(service.Protocol) == "kubernetes" && p.connection.Kubeconfig == "" {
		if err := b.prepareKube(ctx, name, p); err != nil {
			return nil, err
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.workload != client || p.err != nil {
		return nil, errors.Join(connectionruntime.ErrUnprepared, p.err)
	}
	p.ready = true
	b.publishLocked()
	prepared = true
	return p, nil
}
