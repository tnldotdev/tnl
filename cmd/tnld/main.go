package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/0xcadams/tnl/internal/api"
	"github.com/0xcadams/tnl/internal/auth"
	"github.com/0xcadams/tnl/internal/buildinfo"
	"github.com/0xcadams/tnl/internal/certificates"
	"github.com/0xcadams/tnl/internal/config"
	"github.com/0xcadams/tnl/internal/controltls"
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
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "tnld: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 1 && args[0] == "version" {
		_, err := fmt.Fprintln(stdout, buildinfo.Line("tnld"))
		return err
	}
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
		if err := metrics.RegisterDatabase(db); err != nil {
			return errors.Join(err, running.shutdown(cfg.DrainTimeout))
		}
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
	if cfg.Mode.UsesState() && cfg.PublicListen != "" {
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
	store, err := routes.NewStore(d.db, cfg.RouteSuffix, routes.StoreConfig{
		MaxActiveHostnameClaims:  cfg.MaxActiveHostnameClaims,
		MaxHostnameClaimRequests: cfg.MaxHostnameClaimRequests,
		ObserveOperation: func(operation routes.StoreOperation, duration time.Duration, err error) {
			metrics.ObserveSQLiteOperation(string(operation), duration, err)
		},
	})
	if err != nil {
		return nil, nil, err
	}
	bootEpoch, err := newBootEpoch()
	if err != nil {
		return nil, nil, err
	}
	d.coordinator, err = routes.NewCoordinator(ctx, store, bootEpoch, routes.CoordinatorConfig{
		ObserveHeartbeat: func(result routes.HeartbeatResult) {
			metrics.ObserveRouteLeaseHeartbeat(string(result))
		},
		ObserveRouteRemoval: func(reason routes.RouteRemovalReason) {
			metrics.ObserveRouteRemoval(string(reason))
		},
		ObserveWorkerCapacityRejection: func() {
			metrics.IncCapacityRejection("worker_routes")
		},
		ObserveStage: func(stage routes.CoordinatorStage, duration time.Duration) {
			metrics.ObserveRouteCoordinatorStage(string(stage), duration)
		},
	})
	if err != nil {
		return nil, nil, err
	}
	go monitorRoutes(ctx, d.coordinator, metrics)
	var certificateService api.CertificateService
	if cfg.ACMEEnabled() {
		control := new(certificateControl)
		certificateService = control
		// Let routing start while ACME initialization retries in the background.
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
		owner, err := worker.NewEngine(worker.EngineConfig{
			Capacity: cfg.WorkerCapacity, Profiles: profiles, Logf: log.Printf,
			OnTailcatFailure: metrics.IncTailcatFailure,
		})
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
			OnSessionEstablished: func(role workersession.SessionRole) {
				metrics.ObserveWorkerSessionEstablished(string(role))
			},
			OnSessionDisconnected: func(role workersession.SessionRole, reason workersession.DisconnectReason) {
				metrics.ObserveWorkerSessionDisconnected(string(role), string(reason))
			},
		})
		if err != nil {
			return nil, nil, err
		}
		d.workerHub = hub
	}

	controlTLS, err := controltls.New(controltls.Config{
		Hostname: cfg.ControlHostname, StateDir: cfg.StateDir,
		DirectoryURL: cfg.ACMEDirectoryURL, Email: cfg.ACMEEmail, AcceptTerms: cfg.ACMEAcceptTerms,
		CertFile: cfg.ControlCertFile, KeyFile: cfg.ControlKeyFile,
	})
	if err != nil {
		return nil, nil, err
	}
	apiMetrics := coreAPIObserver{metrics: metrics}
	handler := api.NewHandlerWithServicesAndConfig(
		capabilities(cfg.RouteSuffix, cfg.RelayProfile, cfg.ACMEProfile, cfg.ACMEEnabled()),
		authService,
		d.coordinator,
		certificateService,
		api.HandlerConfig{Observer: apiMetrics, ErrorReporter: apiMetrics},
	)
	if hub != nil {
		mux := http.NewServeMux()
		mux.Handle(workerv1.Endpoint, hub)
		mux.Handle("/", handler)
		handler = mux
	}
	publicListener, err := net.Listen("tcp", cfg.PublicListen)
	if err != nil {
		return nil, nil, fmt.Errorf("listen for public ingress: %w", err)
	}
	controlListener := newConnectionListener(publicListener.Addr())
	d.controlListener = controlListener
	d.controlServer = &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		TLSConfig: controlTLS,
	}
	ingressConfig := ingress.Config{
		Lookup: func(hostname string) (worker.RouteBackend, bool) {
			route, ok := d.coordinator.Lookup(hostname)
			return route.Backend, ok
		},
		ControlHostname:    cfg.ControlHostname,
		HandleControl:      controlListener.Enqueue,
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
		_ = d.controlListener.Close()
		return nil, nil, err
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
	// Each session gets a fresh engine because disconnect closes its owner.
	newOwner := func() (worker.RouteOwner, error) {
		return worker.NewEngine(worker.EngineConfig{
			Capacity: cfg.WorkerCapacity, Profiles: profiles, Logf: log.Printf,
			OnTailcatFailure: metrics.IncTailcatFailure,
		})
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
				OnSessionEstablished: func(role workersession.SessionRole) {
					metrics.ObserveWorkerSessionEstablished(string(role))
				},
				OnSessionDisconnected: func(role workersession.SessionRole, reason workersession.DisconnectReason) {
					metrics.ObserveWorkerSessionDisconnected(string(role), string(reason))
				},
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
	// Stop control mutations before draining streams and closing their owners.
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

func capabilities(routeSuffix, relayProfile, acmeProfile string, acmeEnabled bool) corev1.Capabilities {
	result := corev1.Capabilities{
		ProtocolVersions:      []corev1.CapabilitiesProtocolVersions{corev1.CapabilitiesProtocolVersionsN1},
		HostnameAuthorization: []corev1.CapabilitiesHostnameAuthorization{corev1.LocalClaim},
		LocalClaim:            &corev1.LocalClaimCapabilities{Suffix: routeSuffix},
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
	// Prior leases cannot use process-local keys and assignments after restart.
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

type connectionListener struct {
	address     net.Addr
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func newConnectionListener(address net.Addr) *connectionListener {
	return &connectionListener{address: address, connections: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *connectionListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connectionListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *connectionListener) Addr() net.Addr { return l.address }

func (l *connectionListener) Enqueue(connection net.Conn) bool {
	select {
	case l.connections <- connection:
		return true
	case <-l.closed:
		return false
	}
}

func report(err error) {
	if err != nil {
		log.Printf("tnld: %v", err)
	}
}

type coreAPIObserver struct {
	metrics *observability.Metrics
}

func (o coreAPIObserver) ObserveRequest(operation api.Operation, result api.RequestResult, duration time.Duration) {
	o.metrics.ObserveAPIRequest(string(operation), string(result), duration)
}

func (coreAPIObserver) ReportError(err error, requestID string, operation api.Operation) {
	report(fmt.Errorf("core API operation=%s request_id=%s: %w", operation, requestID, err))
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
		stats := coordinator.HealthStats()
		metrics.SetRoutes("provisioning", stats.Provisioning)
		metrics.SetRoutes("active", stats.Active)
		metrics.SetRouteLeaseMinSecondsRemaining("provisioning", stats.MinimumProvisioningLeaseSeconds)
		metrics.SetRouteLeaseMinSecondsRemaining("active", stats.MinimumActiveLeaseSeconds)
		metrics.SetWorkerOwnersConnected(stats.ConnectedOwners)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
