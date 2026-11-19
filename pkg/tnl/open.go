// package tnl publishes an application-owned HTTP handler as an ephemeral service.
package tnl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	"github.com/tnldotdev/tnl/internal/publisher/adhoc"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type RateLimit struct {
	Requests int
	Per      time.Duration
	Burst    int
}

type Limits struct {
	Requests    int
	Rate        RateLimit
	Concurrency int
}

type Options struct {
	// Certificate supplies visitor TLS material; nil selects managed issuance.
	// the callback is polled for replacement and must honor cancellation.
	Certificate func(context.Context) (ServiceCertificate, error)
	// NoTelemetry opts this publication out without changing saved preferences.
	NoTelemetry             bool
	RequirePostQuantum      bool
	EnrollmentKey           string
	PublisherIdentityID     string
	PublisherCredentialFile string
	PublisherIdentity       *PublisherIdentity
	ServerURL               string
	StateDir                string
	HTTPClient              *http.Client
	AccessMode              controlv1.VisitorAccessMode
	IP                      []string
	Limits                  Limits
	StateProtection         StateProtection
	// expiresat is an optional fixed service deadline, not a renewable duration.
	ExpiresAt *time.Time
	// Public defaults to true. set it to false for connector-only access.
	Public *bool
}

// Tunnel owns its local listener, service run, and exact service allocation.
type Tunnel struct {
	cancel      context.CancelFunc
	done        chan struct{}
	mu          sync.Mutex
	service     controlv1.Service
	err         error
	close       sync.Once
	certificate *publisherservice.CertificateExport
}

// Open binds an HTTP handler and returns after its service is routable.
// visitors need current permission unless AccessMode is explicitly anonymous.
func Open(ctx context.Context, handler http.Handler, options Options) (*Tunnel, error) {
	if handler == nil {
		return nil, errors.New("an HTTP handler is required")
	}
	limits := applicationlimits.Limits{Requests: options.Limits.Requests, RateRequests: options.Limits.Rate.Requests,
		RatePer: options.Limits.Rate.Per, RateBurst: options.Limits.Rate.Burst, Concurrency: options.Limits.Concurrency}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	public := options.Public == nil || *options.Public
	state, profile, serverURL, native, err := preparePublisher(ctx, options)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, errors.Join(fmt.Errorf("listen for local HTTP requests: %w", err), state.Close())
	}
	invocationID, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		return nil, errors.Join(err, listener.Close(), state.Close())
	}
	local := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	runCtx, cancel := context.WithCancel(ctx)
	tunnel := &Tunnel{cancel: cancel, done: make(chan struct{}), certificate: new(publisherservice.CertificateExport)}
	serveDone := make(chan error, 1)
	go func() {
		err := local.Serve(listener)
		if failure.Only(err, http.ErrServerClosed) {
			err = nil
		}
		serveDone <- err
		if err != nil {
			cancel()
		}
	}()
	ready := make(chan struct{}, 1)
	go func() {
		result := runHTTPPublication(runCtx, local, serveDone, func(deadline func() time.Time) error {
			return runSDKPublication(runCtx, state, options, adhoc.Options{
				RequirePostQuantum:  options.RequirePostQuantum,
				SuppliedCertificate: suppliedCertificateSource(options.Certificate),
				CertificateExport:   tunnel.certificate,
				ControlURL:          serverURL, HTTPClient: options.HTTPClient, State: profile,
				Publisher: native, InvocationID: invocationID, ExpiresAt: options.ExpiresAt, Public: &public,
				Target: "http://" + listener.Addr().String(), AccessMode: options.AccessMode, IP: slices.Clone(options.IP), Limits: limits,
				OnAllocated: func(service controlv1.Service) error {
					tunnel.mu.Lock()
					tunnel.service = cloneService(service)
					tunnel.mu.Unlock()
					return nil
				},
				Ready: func() error {
					ready <- struct{}{}
					return nil
				},
				ShutdownDeadline: deadline,
			})
		})
		result = errors.Join(result, state.Close())
		tunnel.mu.Lock()
		tunnel.err = result
		tunnel.mu.Unlock()
		close(tunnel.done)
	}()
	select {
	case <-ready:
		if ctx.Err() != nil {
			return nil, errors.Join(context.Cause(ctx), tunnel.Close())
		}
		return tunnel, nil
	case <-tunnel.done:
		if ctx.Err() != nil {
			return nil, errors.Join(context.Cause(ctx), tunnel.Wait())
		}
		if err := tunnel.Wait(); err != nil {
			return nil, err
		}
		return nil, errors.New("ad-hoc publication stopped before it was ready")
	case <-ctx.Done():
		return nil, errors.Join(context.Cause(ctx), tunnel.Close())
	}
}

// ServiceCertificate contains publisher-held PEM, never target TLS settings.
// returned buffers transfer to the publication owner and are cleared after use.
type ServiceCertificate struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

func (ServiceCertificate) String() string   { return "private service certificate" }
func (ServiceCertificate) GoString() string { return "private service certificate" }

type ExportedCertificate struct {
	Certificate ServiceCertificate
	ExpiresAt   time.Time
}

func (ExportedCertificate) String() string   { return "private installed service certificate" }
func (ExportedCertificate) GoString() string { return "private installed service certificate" }

var ErrCertificateUnavailable = publisherservice.ErrCertificateUnavailable

// ExportCertificate copies the current installed certificate and matching key.
// it does not fetch or renew material. the caller owns the returned buffers.
func (t *Tunnel) ExportCertificate(ctx context.Context) (ExportedCertificate, error) {
	if t == nil || t.certificate == nil {
		return ExportedCertificate{}, ErrCertificateUnavailable
	}
	snapshot, err := t.certificate.Snapshot(ctx)
	if err != nil {
		return ExportedCertificate{}, err
	}
	return ExportedCertificate{
		Certificate: ServiceCertificate{CertificatePEM: snapshot.CertificatePEM, PrivateKeyPEM: snapshot.PrivateKeyPEM},
		ExpiresAt:   snapshot.ExpiresAt,
	}, nil
}

func suppliedCertificateSource(source func(context.Context) (ServiceCertificate, error)) func(context.Context) (publisherservice.CertificateMaterial, error) {
	if source == nil {
		return nil
	}
	return func(ctx context.Context) (publisherservice.CertificateMaterial, error) {
		material, err := source(ctx)
		return publisherservice.CertificateMaterial{CertificatePEM: material.CertificatePEM, PrivateKeyPEM: material.PrivateKeyPEM}, err
	}
}

// runHTTPPublication owns the local HTTP listener and one shutdown deadline.
// native cleanup and HTTP drain spend the same remaining time. the timer closes
// owned sockets even while publication cleanup is still joining its workers.
func runHTTPPublication(ctx context.Context, server *http.Server, served <-chan error, publish func(func() time.Time) error) error {
	started, stopped := make(chan struct{}), make(chan struct{})
	deadline := sync.OnceValue(func() time.Time {
		until := time.Now().Add(10 * time.Second)
		close(started)
		return until
	})
	canceled := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() { defer close(canceled); deadline() })
	defer func() {
		if !stopCancellation() {
			<-canceled
		}
	}()
	forced := make(chan error, 1)
	go func() {
		select {
		case <-started:
			timer := time.NewTimer(time.Until(deadline()))
			defer timer.Stop()
			select {
			case <-timer.C:
				forced <- errors.Join(context.DeadlineExceeded, server.Close())
			case <-stopped:
				forced <- nil
			}
		case <-stopped:
			forced <- nil
		}
	}()
	result := publish(deadline)
	shutdown, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline())
	result = errors.Join(result, shutdownHTTP(shutdown, server, served))
	cancel()
	close(stopped)
	return errors.Join(result, <-forced)
}

// shutdownHTTP bounds graceful shutdown, closes remaining connections on timeout,
// and joins the serving loop before the tunnel releases its other resources.
func shutdownHTTP(ctx context.Context, server *http.Server, served <-chan error) error {
	err := server.Shutdown(ctx)
	if err != nil {
		err = errors.Join(err, server.Close())
	}
	return errors.Join(err, <-served)
}

// URL returns the public address, or an empty string for a connector-only service.
func (t *Tunnel) URL() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.service.Endpoint == nil || !t.service.Endpoint.Public {
		return ""
	}
	return "https://" + t.service.Endpoint.Hostname
}

// Service returns a separate snapshot of the allocated ordinary service.
func (t *Tunnel) Service() controlv1.Service {
	t.mu.Lock()
	defer t.mu.Unlock()
	return cloneService(t.service)
}

// Endpoint returns the service hostname, port, and reachability.
func (t *Tunnel) Endpoint() controlv1.ServiceEndpoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.service.Endpoint == nil {
		return controlv1.ServiceEndpoint{}
	}
	return *t.service.Endpoint
}

// Close drains publication and removes the exact service. repeated calls are safe.
func (t *Tunnel) Close() error {
	if t == nil {
		return nil
	}
	t.close.Do(t.cancel)
	return t.Wait()
}

// Wait returns when the publish run and its local listener have stopped.
// exhausting the total request budget is a normal completion.
func (t *Tunnel) Wait() error {
	if t == nil {
		return nil
	}
	<-t.done
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.err
}
