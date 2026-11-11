package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector/kubeconfig"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the loopback address and kubeconfig belong to the listener, not an adapter.
// each replacement owns a new attempt and joins the old transport before reuse.
type ownedServiceListener struct {
	listener *connectorruntime.ListenerSwitch
	kube     serviceKubeconfig
	attempt  *servicePreparation
}

type serviceKubeconfig struct {
	source kubeconfig.Source
	result kubeconfig.Result
}

type servicePreparation struct {
	service controlv1.Service
	cancel  context.CancelFunc
	done    chan struct{}
	state   servicePreparationState // protected by the backend's mu.
}

type servicePreparationState interface{ servicePreparationState() }

type preparingService struct{}
type servingService struct {
	connection      connectorruntime.Connection
	control         connectorstream.Control
	sessionID       string
	authorizedUntil time.Time
}

// a failed startup remains unprepared; failure after publication invalidates the
// prepared read with its original error. neither terminal state can become ready.
type preparationFailed struct{ err error }
type servingFailed struct{ err error }

func (preparingService) servicePreparationState()  {}
func (*servingService) servicePreparationState()   {}
func (preparationFailed) servicePreparationState() {}
func (servingFailed) servicePreparationState()     {}

func (p *servicePreparation) fail(err error) {
	switch p.state.(type) {
	case preparingService:
		p.state = preparationFailed{err}
	case *servingService:
		p.state = servingFailed{err}
	}
}

func (p *servicePreparation) result() (*servingService, error) {
	switch state := p.state.(type) {
	case *servingService:
		return state, nil
	case preparationFailed:
		return nil, state.err
	case servingFailed:
		return nil, state.err
	default:
		return nil, connectorruntime.ErrUnprepared
	}
}

func (p *servicePreparation) matches(service controlv1.Service) bool {
	return p != nil && service.Id == p.service.Id && service.Protocol == p.service.Protocol && service.Endpoint != nil && p.service.Endpoint != nil && *service.Endpoint == *p.service.Endpoint
}

func (p *servicePreparation) serving(client *workload.Client) *servingService {
	serving, ok := p.state.(*servingService)
	if !ok {
		return nil
	}
	if _, current := serving.sessionLease(client, p.service.Id); !current {
		return nil
	}
	return serving
}

func (serving *servingService) sessionLease(client *workload.Client, serviceID string) (time.Time, bool) {
	if client == nil {
		return time.Time{}, true
	}
	session, err := client.Session()
	if err != nil || session.Id != serving.sessionID || !slices.Contains(session.ServiceIds, serviceID) {
		return time.Time{}, false
	}
	return session.LeaseExpiresAt, true
}

func (owner *ownedServiceListener) serving(service controlv1.Service, client *workload.Client) *servingService {
	if owner == nil || !owner.attempt.matches(service) {
		return nil
	}
	return owner.attempt.serving(client)
}

func (owner *ownedServiceListener) kubeconfig() (serviceKubeconfig, bool) {
	if owner == nil || owner.attempt.service.Protocol != controlv1.Kubernetes {
		return serviceKubeconfig{}, false
	}
	switch owner.attempt.state.(type) {
	case *servingService, servingFailed:
		return owner.kube, true
	default:
		return serviceKubeconfig{}, false
	}
}

// preparation is incremental and failure is local to the requested service.
// the exchanged service-ID snapshot is independent of this listener map.
func (b *connectorConnectionBackend) prepareService(ctx context.Context, name string, previous *ownedServiceListener, service controlv1.Service, client *workload.Client) (*servicePreparation, error) {
	if !slices.Contains(b.scope.Services, name) {
		return nil, connectorruntime.ErrUnavailable
	}
	if err := ValidateService(service); err != nil {
		return nil, err
	}
	if string(service.Protocol) != config.Protocol(b.project.Config.Services[name]) {
		return nil, connectorruntime.ErrInvalid
	}
	var control connectorstream.Control
	var err error
	// each new adapter receives a fresh transport ID even when its listener stays.
	identity := ""
	if client != nil {
		control, err = connectorstream.NewWorkloadControl(client)
	} else {
		identity = b.human.identity.Identity.Id
		control, err = connectorstream.NewControl(b.human.authenticated.Control, b.human.store, identity)
	}
	if err != nil {
		return nil, err
	}
	return b.prepareListener(ctx, name, previous, service, client, control, identity)
}

func (b *connectorConnectionBackend) prepareListener(ctx context.Context, name string, previous *ownedServiceListener, service controlv1.Service, client *workload.Client, control connectorstream.Control, identity string) (_ *servicePreparation, result error) {
	// until Serve takes ownership, every exit closes this adapter here.
	defer func() {
		if control != nil {
			cleanup, cancel := context.WithTimeout(b.cleanup(), 5*time.Second)
			defer cancel()
			if err := control.Close(cleanup); err != nil {
				result = errors.Join(result, &connectorstream.CleanupError{Err: err})
			}
		}
	}()
	endpoint := service.Endpoint
	b.mu.Lock()
	deadline := b.deadline
	b.mu.Unlock()
	connection := connectorruntime.Connection{Schema: 1, Protocol: string(service.Protocol), Host: "127.0.0.1", Port: endpoint.Port, ExpiresAt: deadline}
	verification := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname}
	run, err := control.ResolveService(ctx, service.Id)
	if err != nil {
		return nil, err
	}
	if run.Protocol != string(service.Protocol) || run.Endpoint == nil || *run.Endpoint != *endpoint {
		return nil, connectorruntime.ErrUnavailable
	}
	// the service and identity are already validated; the resolved revision must
	// also be valid before Serve accepts ownership of adapter cleanup.
	if run.TrustRevision < 1 {
		return nil, errors.Join(connectorruntime.ErrUnavailable, connectorstream.ErrServiceConnection)
	}
	owner := previous
	if owner == nil {
		port := endpoint.Port
		// independently verified SDK identities cannot share a local capability
		// or compete for the same managed port. metadata retains the remote port.
		if b.parentPID > 0 {
			port = 0
		}
		base, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return nil, err
		}
		owner = &ownedServiceListener{listener: connectorruntime.NewListenerSwitch(base)}
	}
	b.mu.Lock()
	if b.closed || b.workload != client || b.listeners[name] != previous {
		b.mu.Unlock()
		if previous == nil {
			_ = owner.listener.Close()
		}
		return nil, connectorruntime.ErrUnprepared
	}
	lifetime, cancel := context.WithCancel(b.lifetime)
	p := &servicePreparation{service: service, cancel: cancel, done: make(chan struct{}), state: preparingService{}}
	var old *servicePreparation
	if previous != nil {
		old = previous.attempt
	}
	owner.attempt = p
	b.listeners[name] = owner
	b.publishLocked()
	b.mu.Unlock()
	prepared := false
	defer func() {
		if !prepared {
			cancel()
			<-p.done
		}
	}()
	ready := make(chan struct{})
	connection.Port = owner.listener.Addr().(*net.TCPAddr).Port
	configuration := connectorstream.Config{Control: control, ServiceID: service.Id, IdentityID: identity, Protocol: string(service.Protocol), TrustRevision: run.TrustRevision, Endpoint: endpoint, ServiceTLS: verification, CleanupContext: b.cleanup, Ready: func() error { close(ready); return nil }}
	b.workers.Go(func() {
		defer close(p.done)
		if old != nil && old.cancel != nil {
			old.cancel()
			<-old.done
		}
		listener := owner.listener.Next()
		err := func() error {
			defer listener.Close()
			return connectorstream.Serve(lifetime, listener, configuration)
		}()
		b.mu.Lock()
		b.finishPreparationLocked(name, owner, p, err)
		b.mu.Unlock()
	})
	control = nil // the worker's configuration now owns adapter cleanup.
	select {
	case <-ready:
	case <-p.done:
		b.mu.Lock()
		_, err := p.result()
		b.mu.Unlock()
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	serving := &servingService{connection: connection, control: configuration.Control}
	if client != nil {
		session, err := client.Session()
		if err != nil {
			return nil, err
		}
		serving.sessionID = session.Id
	}
	if string(service.Protocol) == "http" || string(service.Protocol) == "kubernetes" {
		serving.connection.URL = "https://" + net.JoinHostPort(endpoint.Hostname, strconv.Itoa(endpoint.Port))
	}
	kube := owner.kube
	if string(service.Protocol) == "kubernetes" && kube.result.File == "" {
		var err error
		kube, err = b.prepareKube(ctx, name, service, connection)
		if err != nil {
			return nil, err
		}
	}
	serving.connection.Kubeconfig, serving.connection.Context = kube.result.File, kube.result.Context
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.publishServiceLocked(name, owner, p, serving, kube, client); err != nil {
		return nil, err
	}
	prepared = true
	return p, nil
}

func (b *connectorConnectionBackend) finishPreparationLocked(name string, owner *ownedServiceListener, p *servicePreparation, err error) {
	// cleanup belongs to the backend even if this attempt has been replaced.
	// lifetime cancellation cannot distinguish retirement from a failed close.
	var cleanup *connectorstream.CleanupError
	if errors.As(err, &cleanup) {
		b.cleanupErr = errors.Join(b.cleanupErr, cleanup.Err)
	}
	if b.listeners[name] != owner || owner.attempt != p {
		return
	}
	p.fail(errors.Join(connectorruntime.ErrUnavailable, err))
	b.publishLocked()
}

func (b *connectorConnectionBackend) publishServiceLocked(name string, owner *ownedServiceListener, p *servicePreparation, serving *servingService, kube serviceKubeconfig, client *workload.Client) error {
	if _, starting := p.state.(preparingService); !starting {
		_, err := p.result()
		return errors.Join(connectorruntime.ErrUnprepared, err)
	}
	if b.closed || b.workload != client || b.listeners[name] != owner || owner.attempt != p || !p.matches(b.services[name]) {
		return connectorruntime.ErrUnprepared
	}
	if _, current := serving.sessionLease(client, p.service.Id); !current {
		return connectorruntime.ErrUnprepared
	}
	transportID, err := opaqueid.New("ctg_")
	if err != nil {
		return err
	}
	serving.connection.TransportID = transportID
	owner.kube = kube
	p.state = serving
	b.publishLocked()
	return nil
}
