package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	adminservice "github.com/tnldotdev/tnl/internal/admin"
	"github.com/tnldotdev/tnl/internal/api"
	"github.com/tnldotdev/tnl/internal/auth"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/backup"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/certificates"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controltls"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/dnsready"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/routes"
	"github.com/tnldotdev/tnl/internal/routeusage"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/internal/worker"
	"github.com/tnldotdev/tnl/internal/workercontrol"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"github.com/tnldotdev/tnl/pkg/protocol/workerv1"
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
	var flags tnldCLI
	parser, err := newTNLDParser(&flags, stdout)
	if err != nil {
		return err
	}
	parsed, err := parser.Parse(args)
	if err != nil {
		return err
	}
	switch parsed.Command() {
	case "serve":
		cfg, err := config.ResolveTNLD(config.TNLD(flags.Serve))
		if err != nil {
			return err
		}
		return serve(ctx, cfg)
	case "version":
		_, err := fmt.Fprintln(stdout, buildinfo.Line("tnld"))
		return err
	default:
		return errors.New("command is required")
	}
}

func newTNLDParser(flags *tnldCLI, output io.Writer) (*kong.Kong, error) {
	return kong.New(
		flags,
		kong.Name("tnld"),
		kong.Description("tnl server."),
		kong.Writers(output, output),
	)
}

type tnldServeCommand config.TNLD

type tnldCLI struct {
	Serve   tnldServeCommand `cmd:"" default:"withargs" help:"Run the tnl server."`
	Version struct{}         `cmd:"" help:"Print release version information."`
}

type daemon struct {
	db                 *sql.DB
	backup             *backup.Manager
	stateLock          *state.DirectoryLock
	login              credentials.LoginToken
	loginRevision      int64
	metricsServer      *observability.Server
	controlListener    net.Listener
	controlServer      *http.Server
	ingress            *ingress.Server
	coordinator        *routes.Coordinator
	workerHub          *workercontrol.Hub
	workerDone         <-chan error
	routeUsageReporter *routeusage.Reporter
	dns                *dnsready.Checker
}

var (
	workerReconnectMin   = time.Second
	workerReconnectMax   = 30 * time.Second
	workerReconnectReset = time.Minute
)

func serve(ctx context.Context, cfg config.TNLD) (result error) {
	lifetime, cancel := context.WithCancel(ctx)
	running := new(daemon)
	defer func() {
		cancel()
		result = errors.Join(result, running.shutdown(cfg.DrainTimeout))
	}()
	metrics := observability.New(string(cfg.Mode))
	done := make(chan error, 4)

	if cfg.Mode.UsesState() {
		stateLock, err := state.LockDirectory(cfg.StateDir)
		if err != nil {
			return err
		}
		running.stateLock = stateLock
		if cfg.BackupURL != "" {
			running.backup, err = backup.New(state.DatabasePath(cfg.StateDir), cfg.BackupURL)
			if err != nil {
				return err
			}
			restored, err := running.backup.Restore(ctx)
			if err != nil {
				return err
			}
			if restored {
				log.Print("restored state database from backup")
			}
		}
		db, err := state.Open(ctx, cfg.StateDir)
		if err != nil {
			return err
		}
		running.db = db
		login, generated, err := state.EnsureLoginToken(ctx, db)
		if err != nil {
			return err
		}
		running.login = login
		running.loginRevision, err = state.ReadLoginTokenRevision(ctx, db)
		if err != nil {
			return err
		}
		if generated {
			log.Print("generated login token; retrieve it with tnl admin server login-token")
		}
		if running.backup != nil {
			if err := running.backup.Start(ctx); err != nil {
				return err
			}
			log.Print("state backup replication started")
		}
		if err := metrics.RegisterDatabase(db); err != nil {
			return err
		}
		if cfg.RouteUsageURL != "" {
			running.routeUsageReporter, err = routeusage.New(db, cfg.RouteUsageURL, cfg.RouteUsageToken, metrics)
			if err != nil {
				return err
			}
			if err := running.routeUsageReporter.Start(lifetime, report); err != nil {
				return err
			}
		}
	}

	if cfg.MetricsListen != "" {
		var err error
		running.metricsServer, err = observability.Listen(cfg.MetricsListen, metrics.Handler())
		if err != nil {
			return fmt.Errorf("listen for metrics: %w", err)
		}
		go forward(done, "serve metrics", running.metricsServer.Done())
	}
	if cfg.Mode == config.TNLDModeWorker && cfg.EdgeURL != "" {
		workerDone, err := startWorker(lifetime, cfg, metrics)
		if err != nil {
			return err
		}
		running.workerDone = workerDone
	}
	if cfg.Mode.UsesState() && cfg.PublicListen != "" {
		controlDone, ingressDone, err := running.startServer(lifetime, cfg, metrics)
		if err != nil {
			return err
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
	return serveErr
}

func (d *daemon) startServer(
	ctx context.Context,
	cfg config.TNLD,
	metrics *observability.Metrics,
) (<-chan error, <-chan error, error) {
	regions, relayRegion, err := relayRegions(ctx, cfg, d.db)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("using relay region %q", relayRegion)
	relayMap, err := config.SelectedRelayMap(regions, relayRegion)
	if err != nil {
		return nil, nil, err
	}
	var oidcVerifier auth.OIDCVerifier
	if cfg.OIDCEnabled() {
		oidcVerifier, err = auth.NewOIDCVerifier(auth.OIDCConfig{
			Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID,
		})
		if err != nil {
			return nil, nil, err
		}
	}
	authService, err := auth.NewService(d.db, auth.ServiceConfig{
		LoginToken: d.login, LoginTokenRevision: d.loginRevision, OIDC: oidcVerifier,
		AccessLifetime: cfg.AccessTokenLifetime, RefreshLifetime: cfg.RefreshTokenLifetime,
	})
	if err != nil {
		return nil, nil, err
	}
	storeConfig := routes.StoreConfig{
		MaxActiveHostnames:  cfg.MaxActiveHostnames,
		MaxHostnameRequests: cfg.MaxHostnameRequests,
		ReservedRouteNames:  cfg.EffectiveReservedRouteNames(),
		VerificationSuffix:  "domains." + cfg.HostnameSuffix(),
		ObserveOperation: func(operation routes.StoreOperation, duration time.Duration, err error) {
			metrics.ObserveSQLiteOperation(string(operation), duration, err)
		},
	}
	if d.routeUsageReporter != nil {
		storeConfig.LifecycleRecorder = d.routeUsageReporter.Store
	}
	dns := d.dns
	if dns == nil {
		resolver := net.DefaultResolver
		if cfg.DNSServer != "" {
			dialer := new(net.Dialer)
			resolver = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, cfg.DNSServer)
				},
			}
		}
		dns = dnsready.NewWithResolver(cfg.ServerHostname(), cfg.HostnameSuffix(), resolver)
	}
	storeConfig.DomainVerifier = dns
	if cfg.SignedAuthorizationEnabled() {
		verifier, err := authorization.NewVerifier(cfg.AuthorizationConfig())
		if err != nil {
			return nil, nil, fmt.Errorf("configure signed authorization: %w", err)
		}
		storeConfig.AuthorizationVerifier = verifier
	}
	store, err := routes.NewStore(d.db, cfg.HostnameSuffix(), storeConfig)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("Checking public DNS for *.%s", cfg.HostnameSuffix())
	go dns.Monitor(ctx, log.Printf)
	serverInstanceID, err := newServerInstanceID()
	if err != nil {
		return nil, nil, err
	}
	d.coordinator, err = routes.NewCoordinator(ctx, store, serverInstanceID, routes.CoordinatorConfig{
		CheckHostnamePublishability: dns.CheckHostname,
		ObserveHeartbeat: func(result routes.HeartbeatResult) {
			metrics.ObserveRouteSessionHeartbeat(string(result))
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
	go monitorGeneratedHostnameCapacity(ctx, store, metrics)
	var certificateService api.CertificateService
	if cfg.ACMEEnabled() {
		control := new(certificateControl)
		certificateService = control
		// Let routing start while ACME initialization retries in the background.
		go control.initialize(ctx, d.db, certificates.Config{
			DirectoryURL:  cfg.ACMEDirectoryURL,
			Email:         cfg.ACMEEmail,
			AcceptTerms:   cfg.ACMEAcceptTerms,
			ACMEProfile:   cfg.ACMEProfile,
			HostnameReady: dns.CheckHostname,
			Probe: func(probeCtx context.Context, issuance certificates.Issuance) error {
				active, ok := d.coordinator.LookupChallenge(issuance.Hostname)
				if !ok || active.RouteID != issuance.RouteID || active.RouteVersion != issuance.RouteVersion {
					return errors.New("assigned challenge route is unavailable")
				}
				return certificates.ProbeTLSALPN(probeCtx, active.Backend, issuance)
			},
		}, report)
	}

	var hub *workercontrol.Hub
	if cfg.Mode == config.TNLDModeStandalone {
		worker, err := worker.NewEngine(worker.EngineConfig{
			Capacity: cfg.WorkerCapacity, Regions: regions, Logf: log.Printf,
			OnTailcatFailure: metrics.IncTailcatFailure,
		})
		if err != nil {
			return nil, nil, err
		}
		if err := d.coordinator.AddWorker("local", worker); err != nil {
			_ = worker.Close()
			return nil, nil, err
		}
		go monitorWorker(ctx, worker, metrics)
	} else {
		verifier, err := credentials.ParseWorkerToken(credentials.WorkerToken(cfg.WorkerToken))
		if err != nil {
			return nil, nil, fmt.Errorf("configure worker token: %w", err)
		}
		hub, err = workercontrol.NewHub(workercontrol.HubConfig{
			Tokens: []credentials.WorkerVerifier{verifier}, Registry: d.coordinator,
			MaxStreams: cfg.WorkerStreamLimit, DrainTime: cfg.DrainTimeout, OnError: report,
			OnSessionEstablished: func(role workercontrol.SessionRole) {
				metrics.ObserveWorkerSessionEstablished(string(role))
			},
			OnSessionDisconnected: func(role workercontrol.SessionRole, reason workercontrol.DisconnectReason) {
				metrics.ObserveWorkerSessionDisconnected(string(role), string(reason))
			},
		})
		if err != nil {
			return nil, nil, err
		}
		d.workerHub = hub
	}

	controlTLS, err := controltls.New(controltls.Config{
		Hostname: cfg.ServerHostname(), Cache: state.ControlTLSCache(d.db, cfg.ACMEDirectoryURL),
		DirectoryURL: cfg.ACMEDirectoryURL, Email: cfg.ACMEEmail, AcceptTerms: cfg.ACMEAcceptTerms,
	})
	if err != nil {
		return nil, nil, err
	}
	apiMetrics := serverAPIObserver{metrics: metrics}
	adminService, err := adminservice.NewService(d.db, d.coordinator, string(cfg.Mode), cfg.DrainTimeout)
	if err != nil {
		return nil, nil, err
	}
	handler := api.NewHandler(api.Config{
		Capabilities: capabilities(cfg, relayRegion), Auth: authService, Routes: d.coordinator,
		Certificates: certificateService, Observer: apiMetrics, ErrorReporter: apiMetrics, RelayMap: relayMap,
		DNSReady: dns.Ready, IngressAddresses: dns.IngressAddresses,
		Readiness: d.db.PingContext, SignedAuthorization: cfg.SignedAuthorizationEnabled(), Admin: adminService,
	})
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
		Lookup: func(hostname string) (ingress.Route, bool) {
			route, ok := d.coordinator.Lookup(hostname)
			return ingress.Route{
				ID: route.RouteID, RouteVersion: route.RouteVersion,
				AllowedIPPrefixes: route.AllowedIPPrefixes, Backend: route.Backend,
			}, ok
		},
		ServerHostname:     cfg.ServerHostname(),
		HandleControl:      controlListener.Enqueue,
		RequireProxyHeader: cfg.RequireProxyHeader, MaxConnections: cfg.PublicConnLimit,
		MaxRouteConnections: cfg.RouteConnLimit, Metrics: metrics, OnError: report,
	}
	if d.routeUsageReporter != nil {
		ingressConfig.OpenUsage = func(routeID string, routeVersion uint64, source netip.Addr, at time.Time) ingress.UsageConnection {
			return d.routeUsageReporter.Collector.Open(routeID, routeVersion, source, at)
		}
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
	log.Printf("Control available at https://%s", cfg.ServerHostname())
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
	routeVersion uint64,
	profile string,
	csrDER []byte,
) (certificates.Issuance, error) {
	service := c.service.Load()
	if service == nil {
		return certificates.Issuance{}, certificates.ErrUnavailable
	}
	return service.Create(ctx, routeID, routeVersion, profile, csrDER)
}

func (c *certificateControl) Get(ctx context.Context, id string) (certificates.Issuance, error) {
	service := c.service.Load()
	if service == nil {
		return certificates.Issuance{}, certificates.ErrUnavailable
	}
	return service.Get(ctx, id)
}

func (c *certificateControl) ChallengeReady(ctx context.Context, id string) (certificates.Issuance, error) {
	service := c.service.Load()
	if service == nil {
		return certificates.Issuance{}, certificates.ErrUnavailable
	}
	return service.ChallengeReady(ctx, id)
}

func (c *certificateControl) ChallengeRemoved(ctx context.Context, id string) (certificates.Issuance, error) {
	service := c.service.Load()
	if service == nil {
		return certificates.Issuance{}, certificates.ErrUnavailable
	}
	return service.ChallengeRemoved(ctx, id)
}

func (c *certificateControl) Installed(
	ctx context.Context,
	id, routeID string,
	routeVersion uint64,
) (certificates.Issuance, error) {
	service := c.service.Load()
	if service == nil {
		return certificates.Issuance{}, certificates.ErrUnavailable
	}
	return service.Installed(ctx, id, routeID, routeVersion)
}

func startWorker(ctx context.Context, cfg config.TNLD, metrics *observability.Metrics) (<-chan error, error) {
	edgeURL, err := url.Parse(cfg.EdgeURL)
	if err != nil {
		return nil, err
	}
	serverScheme := "https"
	if edgeURL.Scheme == "ws" {
		serverScheme = "http"
	}
	server, err := serverclient.New((&url.URL{Scheme: serverScheme, Host: edgeURL.Host}).String(), nil, "")
	if err != nil {
		return nil, err
	}
	token := credentials.WorkerToken(cfg.WorkerToken)
	if _, err := credentials.ParseWorkerToken(token); err != nil {
		return nil, fmt.Errorf("configure worker token: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		backoff := workerReconnectMin
		for {
			relayMap, relayErr := server.RelayMap(ctx)
			if relayErr != nil {
				if ctx.Err() != nil {
					done <- nil
					return
				}
				report(fmt.Errorf("read edge relay map: %w", relayErr))
				if !waitWorkerReconnect(ctx, backoff) {
					done <- nil
					return
				}
				backoff = min(backoff*2, workerReconnectMax)
				continue
			}
			regions, relayErr := config.DecodeRelayRegions(relayMap)
			if relayErr != nil {
				done <- relayErr
				return
			}
			// Each session gets a fresh map and engine because disconnect closes its worker.
			worker, ownerErr := worker.NewEngine(worker.EngineConfig{
				Capacity: cfg.WorkerCapacity, Regions: regions, Logf: log.Printf,
				OnTailcatFailure: metrics.IncTailcatFailure,
			})
			if ownerErr != nil {
				done <- ownerErr
				return
			}
			sessionCtx, cancelSession := context.WithCancel(ctx)
			go monitorWorker(sessionCtx, worker, metrics)
			started := time.Now()
			runErr := workercontrol.RunWorker(ctx, workercontrol.WorkerConfig{
				URL: cfg.EdgeURL, Token: token, Worker: worker, MaxStreams: cfg.WorkerStreamLimit,
				DrainTime: cfg.DrainTimeout, OnError: report,
				OnSessionEstablished: func(role workercontrol.SessionRole) {
					metrics.ObserveWorkerSessionEstablished(string(role))
				},
				OnSessionDisconnected: func(role workercontrol.SessionRole, reason workercontrol.DisconnectReason) {
					metrics.ObserveWorkerSessionDisconnected(string(role), string(reason))
				},
			})
			cancelSession()
			closeErr := worker.Close()
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
			if !waitWorkerReconnect(ctx, backoff) {
				done <- nil
				return
			}
			backoff = min(backoff*2, workerReconnectMax)
		}
	}()
	return done, nil
}

func waitWorkerReconnect(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (d *daemon) shutdown(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var result error
	// Stop control mutations before draining streams and closing their workers.
	if d.controlServer != nil {
		if err := d.controlServer.Shutdown(ctx); err != nil {
			result = errors.Join(result, err, d.controlServer.Close())
		}
	}
	if d.ingress != nil {
		result = errors.Join(result, d.ingress.Drain(ctx))
	}
	if d.workerHub != nil {
		result = errors.Join(result, d.workerHub.Shutdown(ctx))
		d.workerHub = nil
	}
	if d.coordinator != nil {
		result = errors.Join(result, d.coordinator.Close())
	}
	if d.routeUsageReporter != nil {
		result = errors.Join(result, d.routeUsageReporter.Close(ctx))
		d.routeUsageReporter = nil
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
		d.db = nil
	}
	if d.backup != nil {
		backupCtx, cancelBackup := context.WithTimeout(context.Background(), min(timeout, 15*time.Second))
		result = errors.Join(result, d.backup.Close(backupCtx))
		cancelBackup()
		d.backup = nil
	}
	if d.stateLock != nil {
		result = errors.Join(result, d.stateLock.Close())
		d.stateLock = nil
	}
	return result
}

func relayRegions(ctx context.Context, cfg config.TNLD, db *sql.DB) (map[string]*tailcfg.DERPRegion, string, error) {
	if cfg.RelayMapFile == "" && cfg.RelayProvider == "tailcat" {
		return config.LoadTailcatRelayRegions(ctx, db, false)
	}
	regions, err := config.LoadRelayRegions(cfg.RelayMapFile)
	if err != nil {
		return nil, "", err
	}
	region, err := config.SelectRelayRegion(regions, cfg.RelayRegion)
	if err != nil {
		return nil, "", err
	}
	return regions, region, nil
}

func capabilities(cfg config.TNLD, relayRegion string) serverv1.Capabilities {
	result := serverv1.Capabilities{
		ProtocolVersions: []serverv1.CapabilitiesProtocolVersions{serverv1.CapabilitiesProtocolVersionsN1},
		Administration: serverv1.AdministrationCapabilities{
			Version: serverv1.AdministrationCapabilitiesVersionN1,
			Operations: []serverv1.AdministrationCapabilitiesOperations{
				serverv1.ServerStatus, serverv1.Routes, serverv1.Hostnames, serverv1.Credentials,
				serverv1.ControlSessions, serverv1.MaintenanceControls,
			},
		},
		Authentication: serverv1.AuthenticationCapabilities{
			Required: serverv1.True,
			Methods:  []serverv1.AuthenticationCapabilitiesMethods{serverv1.LoginToken},
		},
		HostnameAuthorization: []serverv1.CapabilitiesHostnameAuthorization{serverv1.LocalHostnames},
		HostnameSuffix:        cfg.HostnameSuffix(),
		TemporaryNameSupport:  true,
		PersistentBaseSupport: true,
		CustomDomainSupport:   true,
		MaximumSubdomainDepth: routes.MaximumSubdomainDepth,
		IngressIpv4:           []string{},
		IngressIpv6:           []string{},
		LocalHostnames:        &serverv1.LocalHostnameCapabilities{Suffix: cfg.HostnameSuffix()},
		Transport: serverv1.TransportCapabilities{
			Type: serverv1.Tailcat, Version: serverv1.TransportCapabilitiesVersionN1, RelayRegion: relayRegion,
		},
	}
	if cfg.SignedAuthorizationEnabled() {
		result.HostnameAuthorization = []serverv1.CapabilitiesHostnameAuthorization{serverv1.SignedAuthorization}
		result.AuthorizationAuthorityEndpoint = &cfg.AuthorizationAuthorityEndpoint
		result.LocalHostnames = nil
	}
	if cfg.OIDCEnabled() {
		result.Authentication.Methods = append(result.Authentication.Methods, serverv1.Oidc)
		result.Oidc = &serverv1.OIDCCapabilities{
			Issuer: cfg.OIDCIssuer, ClientId: cfg.OIDCClientID,
			LoginFlow: serverv1.OIDCCapabilitiesLoginFlow(cfg.OIDCLoginFlow),
		}
	}
	if cfg.ACMEEnabled() {
		result.Acme = &serverv1.AcmeCapabilities{AcmeProfile: cfg.ACMEProfile}
	}
	return result
}

func newServerInstanceID() (string, error) {
	// Fence process-local assignments; an exact signed retry may explicitly restore its session.
	return opaqueid.New("instance_")
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

type serverAPIObserver struct {
	metrics *observability.Metrics
}

func (o serverAPIObserver) ObserveRequest(operation api.Operation, result api.RequestResult, duration time.Duration) {
	o.metrics.ObserveAPIRequest(string(operation), string(result), duration)
}

func (serverAPIObserver) ReportError(err error, requestID string, operation api.Operation) {
	report(fmt.Errorf("server API operation=%s request_id=%s: %w", operation, requestID, err))
}

func monitorWorker(ctx context.Context, worker worker.RouteWorker, metrics *observability.Metrics) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		capacity := worker.Capacity()
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
		metrics.SetRoutes("routable", stats.Routable)
		metrics.SetRouteSessionMinSecondsRemaining("provisioning", stats.MinimumProvisioningSessionSeconds)
		metrics.SetRouteSessionMinSecondsRemaining("routable", stats.MinimumRoutableSessionSeconds)
		metrics.SetWorkersConnected(stats.ConnectedWorkers)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func monitorGeneratedHostnameCapacity(ctx context.Context, store *routes.Store, metrics *observability.Metrics) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		total, remaining, err := store.GeneratedHostnameCapacity(ctx)
		if err == nil {
			metrics.SetGeneratedHostnameCapacity(total, remaining)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
