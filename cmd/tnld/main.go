package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/0xcadams/tnl/internal/api"
	"github.com/0xcadams/tnl/internal/auth"
	"github.com/0xcadams/tnl/internal/certificates"
	"github.com/0xcadams/tnl/internal/config"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/ingress"
	"github.com/0xcadams/tnl/internal/observability"
	"github.com/0xcadams/tnl/internal/routes"
	"github.com/0xcadams/tnl/internal/state"
	"github.com/0xcadams/tnl/internal/worker"
	"github.com/0xcadams/tnl/internal/workersession"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
	"github.com/0xcadams/tnl/pkg/protocol/workerv1"
	"tailscale.com/tailcfg"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "tnld: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	cfg, err := config.ParseTNLD(args)
	if err != nil {
		return err
	}
	return serve(ctx, cfg)
}

type daemon struct {
	db              *sql.DB
	metricsServer   *observability.Server
	controlListener net.Listener
	controlServer   *http.Server
	ingress         *ingress.Server
	coordinator     *routes.Coordinator
	workerHub       *workersession.Hub
	workerDone      <-chan error
}

var (
	workerReconnectMin   = time.Second
	workerReconnectMax   = 30 * time.Second
	workerReconnectReset = time.Minute
)

func serve(ctx context.Context, cfg config.TNLD) error {
	lifetime, cancel := context.WithCancel(ctx)
	defer cancel()
	running := new(daemon)
	metrics := observability.New(string(cfg.Mode))
	done := make(chan error, 4)

	if cfg.Mode.UsesState() {
		db, err := state.Open(ctx, cfg.StateDir)
		if err != nil {
			return err
		}
		running.db = db
	}

	if cfg.MetricsListen != "" {
		var err error
		running.metricsServer, err = observability.Listen(cfg.MetricsListen, metrics.Handler())
		if err != nil {
			return errors.Join(fmt.Errorf("listen for metrics: %w", err), running.shutdown(cfg.DrainTimeout))
		}
		go forward(done, "serve metrics", running.metricsServer.Done())
	}
	if cfg.Mode == config.TNLDModeWorker && cfg.WorkerURL != "" {
		workerDone, err := startWorker(lifetime, cfg, metrics)
		if err != nil {
			return errors.Join(err, running.shutdown(cfg.DrainTimeout))
		}
		running.workerDone = workerDone
	}
	if cfg.Mode.UsesState() && cfg.ControlListen != "" {
		controlDone, ingressDone, err := running.startCore(lifetime, cfg, metrics)
		if err != nil {
			return errors.Join(err, running.shutdown(cfg.DrainTimeout))
		}
		go forward(done, "serve control API", controlDone)
		if ingressDone != nil {
			go forward(done, "serve public ingress", ingressDone)
		}
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-done:
	case serveErr = <-running.workerDone:
		if serveErr != nil {
			serveErr = fmt.Errorf("run worker: %w", serveErr)
		}
		running.workerDone = nil
	}
	cancel()
	return errors.Join(serveErr, running.shutdown(cfg.DrainTimeout))
}

func (d *daemon) startCore(
	ctx context.Context,
	cfg config.TNLD,
	metrics *observability.Metrics,
) (<-chan error, <-chan error, error) {
	authService, err := auth.NewService(d.db, credentials.BootstrapToken(cfg.BootstrapToken))
	if err != nil {
		return nil, nil, err
	}
	store, err := routes.NewStore(d.db)
	if err != nil {
		return nil, nil, err
	}
	bootEpoch, err := newBootEpoch()
	if err != nil {
		return nil, nil, err
	}
	d.coordinator, err = routes.NewCoordinator(ctx, store, bootEpoch)
	if err != nil {
		return nil, nil, err
	}
	go monitorRoutes(ctx, d.coordinator, metrics)
	var certificateService api.CertificateService
	if cfg.ACMEEnabled() {
		control := new(certificateControl)
		certificateService = control
		go control.initialize(ctx, d.db, certificates.Config{
			DirectoryURL: cfg.ACMEDirectoryURL,
			Email:        cfg.ACMEEmail,
			AcceptTerms:  cfg.ACMEAcceptTerms,
			Profile:      cfg.ACMEProfile,
			Probe: func(probeCtx context.Context, job certificates.Job) error {
				active, ok := d.coordinator.LookupChallenge(job.Hostname)
				if !ok || active.RouteID != job.RouteID || active.Generation != job.Generation {
					return errors.New("assigned challenge route is unavailable")
				}
				return certificates.ProbeTLSALPN(probeCtx, active.Backend, job)
			},
		}, report)
	}

	var hub *workersession.Hub
	if cfg.Mode == config.TNLDModeStandalone {
		profiles, err := relayProfiles(cfg)
		if err != nil {
			return nil, nil, err
		}
		owner, err := worker.NewEngine(worker.EngineConfig{Capacity: cfg.WorkerCapacity, Profiles: profiles, Logf: log.Printf})
		if err != nil {
			return nil, nil, err
		}
		if err := d.coordinator.AddOwner("local", owner); err != nil {
			_ = owner.Close()
			return nil, nil, err
		}
		go monitorWorker(ctx, owner, metrics)
	} else {
		verifier, err := credentials.ParseWorkerToken(credentials.WorkerToken(cfg.WorkerToken))
		if err != nil {
			return nil, nil, fmt.Errorf("configure worker token: %w", err)
		}
		hub, err = workersession.NewHub(workersession.HubConfig{
			Tokens: []credentials.WorkerVerifier{verifier}, Registry: d.coordinator,
			MaxStreams: cfg.WorkerStreamLimit, DrainTime: cfg.DrainTimeout, OnError: report,
		})
		if err != nil {
			return nil, nil, err
		}
		d.workerHub = hub
	}

	certificate, err := tls.LoadX509KeyPair(cfg.ControlCertFile, cfg.ControlKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load control certificate: %w", err)
	}
	handler := api.NewHandlerWithServices(
		capabilities(cfg.RelayProfile, cfg.ACMEProfile, cfg.ACMEEnabled()),
		authService,
		d.coordinator,
		certificateService,
	)
	if hub != nil {
		mux := http.NewServeMux()
		mux.Handle(workerv1.Endpoint, hub)
		mux.Handle("/", handler)
		handler = mux
	}
	d.controlListener, err = net.Listen("tcp", cfg.ControlListen)
	if err != nil {
		return nil, nil, fmt.Errorf("listen for control API: %w", err)
	}
	d.controlServer = &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13},
	}
	controlDone := make(chan error, 1)
	go func() {
		err := d.controlServer.ServeTLS(d.controlListener, "", "")
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		controlDone <- err
		close(controlDone)
	}()

	if cfg.PublicListen == "" {
		return controlDone, nil, nil
	}
	publicListener, err := net.Listen("tcp", cfg.PublicListen)
	if err != nil {
		return nil, nil, fmt.Errorf("listen for public ingress: %w", err)
	}
	ingressConfig := ingress.Config{
		Lookup: func(hostname string) (worker.RouteBackend, bool) {
			route, ok := d.coordinator.Lookup(hostname)
			return route.Backend, ok
		},
		RequireProxyHeader: cfg.RequireProxyHeader, MaxConnections: cfg.PublicConnLimit,
		MaxRouteConnections: cfg.RouteConnLimit, Metrics: metrics, OnError: report,
	}
	if cfg.ACMEEnabled() {
		ingressConfig.LookupChallenge = func(hostname string) (worker.RouteBackend, bool) {
			route, ok := d.coordinator.LookupChallenge(hostname)
			return route.Backend, ok
		}
	}
	d.ingress, err = ingress.New(publicListener, ingressConfig)
	if err != nil {
		_ = publicListener.Close()
		return nil, nil, err
	}
	ingressDone := make(chan error, 1)
	go func() {
		ingressDone <- d.ingress.Serve()
		close(ingressDone)
	}()
	return controlDone, ingressDone, nil
}

type certificateControl struct {
	service atomic.Pointer[certificates.Service]
}

func (c *certificateControl) initialize(
	ctx context.Context,
	db *sql.DB,
	config certificates.Config,
	onError func(error),
) {
	for {
		service, err := certificates.New(ctx, db, config)
		if err == nil {
			c.service.Store(service)
			return
		}
		onError(fmt.Errorf("initialize automatic certificates: %w", err))
		timer := time.NewTimer(30 * time.Second)
		select {
		case <-ctx.Done():
			_ = timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c *certificateControl) Create(
	ctx context.Context,
	routeID string,
	generation uint64,
	profile string,
	csrDER []byte,
) (certificates.Job, error) {
	service := c.service.Load()
	if service == nil {
		return certificates.Job{}, certificates.ErrUnavailable
	}
	return service.Create(ctx, routeID, generation, profile, csrDER)
}

func (c *certificateControl) Get(ctx context.Context, id string) (certificates.Job, error) {
	service := c.service.Load()
	if service == nil {
		return certificates.Job{}, certificates.ErrUnavailable
	}
	return service.Get(ctx, id)
}

func (c *certificateControl) ChallengeReady(ctx context.Context, id string) (certificates.Job, error) {
	service := c.service.Load()
	if service == nil {
		return certificates.Job{}, certificates.ErrUnavailable
	}
	return service.ChallengeReady(ctx, id)
}

func (c *certificateControl) ChallengeRemoved(ctx context.Context, id string) (certificates.Job, error) {
	service := c.service.Load()
	if service == nil {
		return certificates.Job{}, certificates.ErrUnavailable
	}
	return service.ChallengeRemoved(ctx, id)
}

func (c *certificateControl) Installed(
	ctx context.Context,
	id, routeID string,
	generation uint64,
) (certificates.Job, error) {
	service := c.service.Load()
	if service == nil {
		return certificates.Job{}, certificates.ErrUnavailable
	}
	return service.Installed(ctx, id, routeID, generation)
}

func startWorker(ctx context.Context, cfg config.TNLD, metrics *observability.Metrics) (<-chan error, error) {
	profiles, err := relayProfiles(cfg)
	if err != nil {
		return nil, err
	}
	token := credentials.WorkerToken(cfg.WorkerToken)
	if _, err := credentials.ParseWorkerToken(token); err != nil {
		return nil, fmt.Errorf("configure worker token: %w", err)
	}
	newOwner := func() (worker.RouteOwner, error) {
		return worker.NewEngine(worker.EngineConfig{Capacity: cfg.WorkerCapacity, Profiles: profiles, Logf: log.Printf})
	}
	owner, err := newOwner()
	if err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		backoff := workerReconnectMin
		for {
			sessionCtx, cancelSession := context.WithCancel(ctx)
			go monitorWorker(sessionCtx, owner, metrics)
			started := time.Now()
			runErr := workersession.RunWorker(ctx, workersession.WorkerConfig{
				URL: cfg.WorkerURL, Token: token, Owner: owner, MaxStreams: cfg.WorkerStreamLimit,
				DrainTime: cfg.DrainTimeout, OnError: report,
			})
			cancelSession()
			closeErr := owner.Close()
			if ctx.Err() != nil {
				done <- closeErr
				return
			}
			if runErr != nil {
				report(fmt.Errorf("worker session disconnected: %w", runErr))
			}
			if closeErr != nil {
				report(closeErr)
			}
			if time.Since(started) >= workerReconnectReset {
				backoff = workerReconnectMin
			}
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				_ = timer.Stop()
				done <- nil
				return
			case <-timer.C:
			}
			backoff = min(backoff*2, workerReconnectMax)
			owner, err = newOwner()
			if err != nil {
				done <- err
				return
			}
		}
	}()
	return done, nil
}

func (d *daemon) shutdown(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var result error
	if d.controlServer != nil {
		if err := d.controlServer.Shutdown(ctx); err != nil {
			result = errors.Join(result, err, d.controlServer.Close())
		}
	}
	if d.ingress != nil {
		result = errors.Join(result, d.ingress.Drain(ctx))
	}
	if d.workerHub != nil {
		d.workerHub.Close()
	}
	if d.coordinator != nil {
		result = errors.Join(result, d.coordinator.Close())
	}
	if d.workerDone != nil {
		select {
		case err := <-d.workerDone:
			result = errors.Join(result, err)
		case <-ctx.Done():
			result = errors.Join(result, ctx.Err())
		}
	}
	if d.metricsServer != nil {
		result = errors.Join(result, d.metricsServer.Shutdown(ctx))
	}
	if d.db != nil {
		if err := d.db.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("close state: %w", err))
		}
	}
	return result
}

func relayProfiles(cfg config.TNLD) (map[string]*tailcfg.DERPRegion, error) {
	profiles, err := config.LoadRelayProfiles(cfg.RelayMapFile)
	if err != nil {
		return nil, err
	}
	if cfg.Mode == config.TNLDModeStandalone && profiles[cfg.RelayProfile] == nil {
		return nil, fmt.Errorf("relay profile %q is absent from the relay map", cfg.RelayProfile)
	}
	return profiles, nil
}

func capabilities(relayProfile, acmeProfile string, acmeEnabled bool) corev1.Capabilities {
	result := corev1.Capabilities{
		ProtocolVersions:      []corev1.CapabilitiesProtocolVersions{corev1.CapabilitiesProtocolVersionsN1},
		HostnameAuthorization: []corev1.CapabilitiesHostnameAuthorization{corev1.LocalClaim},
		Transport: corev1.TransportCapabilities{
			Type: corev1.Tailcat, Version: corev1.TransportCapabilitiesVersionN1, RelayProfile: relayProfile,
		},
	}
	if acmeEnabled {
		result.Acme = &corev1.AcmeCapabilities{Profile: acmeProfile}
	}
	return result
}

func newBootEpoch() (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", err
	}
	return "boot_" + hex.EncodeToString(material[:]), nil
}

func forward(destination chan<- error, name string, source <-chan error) {
	err := <-source
	if err != nil {
		err = fmt.Errorf("%s: %w", name, err)
	}
	destination <- err
}

func report(err error) {
	if err != nil {
		log.Printf("tnld: %v", err)
	}
}

func monitorWorker(ctx context.Context, owner worker.RouteOwner, metrics *observability.Metrics) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		capacity := owner.Capacity()
		metrics.SetWorkerRoutes(capacity.Active)
		metrics.SetWorkerCapacity(capacity.Limit)
		metrics.SetWorkerDraining(capacity.Draining)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func monitorRoutes(ctx context.Context, coordinator *routes.Coordinator, metrics *observability.Metrics) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		provisioning, active := coordinator.Stats()
		metrics.SetRoutes("provisioning", provisioning)
		metrics.SetRoutes("active", active)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
