package publication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/api"
	"github.com/0xcadams/tnl/internal/auth"
	"github.com/0xcadams/tnl/internal/certificates"
	"github.com/0xcadams/tnl/internal/clientstate"
	"github.com/0xcadams/tnl/internal/coreclient"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/ingress"
	"github.com/0xcadams/tnl/internal/routes"
	corestate "github.com/0xcadams/tnl/internal/state"
	"github.com/0xcadams/tnl/internal/testutil/integrationtest"
	"github.com/0xcadams/tnl/internal/worker"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

func TestIntegrationAutomaticCertificatePublicationRestartAndRenewal(t *testing.T) {
	pebblePath := integrationtest.RequirePebble(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const hostname = "route.tnl.test"

	publicListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publicListener.Close() })
	dnsAddress := integrationtest.StartChallengeDNS(t)
	pebble := integrationtest.StartPebble(
		t, pebblePath, publicListener.Addr().(*net.TCPAddr).Port, dnsAddress,
	)
	issuerRoots := pebble.IssuerRoots(t)
	region := integrationtest.DERP(t)
	profiles := map[string]*tailcfg.DERPRegion{"test": region}

	database, err := corestate.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	bootstrap, err := credentials.NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.NewService(database, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	routeStore, err := routes.NewStore(database, "tnl.test")
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := routes.NewCoordinator(ctx, routeStore, "boot_integration")
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Close()
	engine, err := worker.NewEngine(worker.EngineConfig{Capacity: 4, Profiles: profiles, Logf: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AddOwner("local", engine); err != nil {
		t.Fatal(err)
	}

	ingressErrors := make(chan error, 8)
	publicIngress, err := ingress.New(publicListener, ingress.Config{
		Lookup: func(name string) (worker.RouteBackend, bool) {
			active, ok := coordinator.Lookup(name)
			return active.Backend, ok
		},
		LookupChallenge: func(name string) (worker.RouteBackend, bool) {
			active, ok := coordinator.LookupChallenge(name)
			return active.Backend, ok
		},
		MaxConnections: 32, MaxRouteConnections: 8,
		OnError: func(err error) { ingressErrors <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	ingressDone := make(chan error, 1)
	go func() { ingressDone <- publicIngress.Serve() }()
	defer func() {
		drainContext, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := publicIngress.Drain(drainContext); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("drain ingress: %v", err)
		}
		if err := <-ingressDone; err != nil {
			t.Errorf("serve ingress: %v", err)
		}
	}()

	certificateService, err := certificates.New(ctx, database, certificates.Config{
		DirectoryURL: pebble.DirectoryURL(), Email: "operator@example.com", AcceptTerms: true,
		Profile: "tlsserver", HTTPClient: pebble.HTTPClient(), Roots: issuerRoots,
		Probe: func(probeContext context.Context, job certificates.Job) error {
			active, ok := coordinator.LookupChallenge(job.Hostname)
			if !ok || active.RouteID != job.RouteID || active.Generation != job.Generation {
				return errors.New("assigned challenge route is unavailable")
			}
			return certificates.ProbeTLSALPN(probeContext, active.Backend, job)
		},
	})
	if err != nil {
		t.Fatalf("initialize certificate service: %v; Pebble logs:\n%s", err, pebble.Logs())
	}
	capabilities := corev1.Capabilities{
		ProtocolVersions:      []corev1.CapabilitiesProtocolVersions{corev1.CapabilitiesProtocolVersionsN1},
		HostnameAuthorization: []corev1.CapabilitiesHostnameAuthorization{corev1.LocalClaim},
		Transport: corev1.TransportCapabilities{
			Type: corev1.Tailcat, Version: corev1.TransportCapabilitiesVersionN1, RelayProfile: "test",
		},
		Acme: &corev1.AcmeCapabilities{Profile: "tlsserver"},
	}
	controlServer := httptest.NewTLSServer(api.NewHandlerWithServices(
		capabilities, authService, coordinator, certificateService,
	))
	defer controlServer.Close()
	anonymous, err := coreclient.New(controlServer.URL, controlServer.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := anonymous.Exchange(ctx, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	client, err := coreclient.New(
		controlServer.URL, controlServer.Client(), credentials.AccessToken(issued.AccessToken),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ClaimHostname(ctx, "route", "pebble-integration"); err != nil {
		t.Fatal(err)
	}

	requestDetails := make(chan *http.Request, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestDetails <- request.Clone(context.Background())
		_, _ = io.WriteString(response, "publication reached loopback")
	}))
	defer origin.Close()
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	agentState, err := clientstate.New(stateRoot, controlServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	publicationConfig := PublicConfig{
		Core: client, Hostname: hostname, Target: origin.URL, State: agentState, ACMEProfile: "tlsserver",
		RelayProfile: "test", Profiles: profiles, DrainTime: 5 * time.Second, Logf: logger.Discard,
	}
	firstRun := startIntegrationPublication(ctx, publicationConfig)
	defer firstRun.Stop(t)
	firstRun.WaitReady(t, ctx, hostname, pebble)

	browserTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: issuerRoots, NextProtos: []string{"http/1.1"},
		},
		DialContext: func(dialContext context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(dialContext, network, publicListener.Addr().String())
		},
		ForceAttemptHTTP2: false,
	}
	defer browserTransport.CloseIdleConnections()
	browser := &http.Client{Transport: browserTransport, Timeout: 20 * time.Second}
	requestPublication := func() []byte {
		t.Helper()
		browserTransport.CloseIdleConnections()
		response, err := browser.Get("https://" + hostname + "/acceptance")
		if err != nil {
			t.Fatalf("browser request: %v; Pebble logs:\n%s", err, pebble.Logs())
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal(errors.Join(readErr, closeErr))
		}
		if response.StatusCode != http.StatusOK || string(body) != "publication reached loopback" ||
			response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
			t.Fatalf("browser response = %d %q, TLS = %+v", response.StatusCode, body, response.TLS)
		}
		select {
		case request := <-requestDetails:
			if request.Host != hostname || request.Header.Get("X-Forwarded-For") != "127.0.0.1" {
				t.Fatalf("loopback request host = %q, forwarded-for = %q", request.Host, request.Header.Get("X-Forwarded-For"))
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		return bytes.Clone(response.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	}
	initialSPKI := requestPublication()

	listed, err := client.ListRoutes(ctx)
	if err != nil || len(listed) != 1 {
		t.Fatalf("routes = %+v, %v", listed, err)
	}
	routeID := listed[0].Id
	assertPersistedPublication(t, database, routeID, 1)
	firstRun.Stop(t)
	initial := readCurrentMaterial(t, agentState, routeID, hostname)

	freshRestart := startIntegrationPublication(ctx, publicationConfig)
	defer freshRestart.Stop(t)
	freshRestart.WaitReady(t, ctx, hostname, pebble)
	if restartedSPKI := requestPublication(); !bytes.Equal(restartedSPKI, initialSPKI) {
		t.Fatal("restart replaced a certificate before its renewal time")
	}
	assertPersistedPublication(t, database, routeID, 1)
	freshRestart.Stop(t)
	fresh := readCurrentMaterial(t, agentState, routeID, hostname)
	if fresh.OrderID != initial.OrderID || fresh.Generation != initial.Generation {
		t.Fatalf("fresh restart changed certificate state from %+v to %+v", initial, fresh)
	}

	due := time.Now().Add(-time.Second).UTC()
	if !due.After(fresh.Certificate.Leaf.NotBefore) {
		due = fresh.Certificate.Leaf.NotBefore.Add(time.Second)
		if wait := time.Until(due.Add(time.Millisecond)); wait > 0 {
			time.Sleep(wait)
		}
	}
	forceRenewalDue(t, database, stateRoot, controlServer.URL, routeID, fresh.OrderID, due)
	renewalRun := startIntegrationPublication(ctx, publicationConfig)
	defer renewalRun.Stop(t)
	renewalRun.WaitReady(t, ctx, hostname, pebble)
	assertPersistedPublication(t, database, routeID, 2)
	replacementSPKI := requestPublication()
	if bytes.Equal(replacementSPKI, initialSPKI) {
		t.Fatal("due restart did not rotate the application key")
	}
	renewalRun.Stop(t)
	replacement := readCurrentMaterial(t, agentState, routeID, hostname)
	if !replacement.Installed || replacement.OrderID == initial.OrderID ||
		replacement.Generation <= initial.Generation || !replacement.RenewAt.After(time.Now()) {
		t.Fatalf("renewed agent certificate = %+v", replacement)
	}
	select {
	case err := <-ingressErrors:
		t.Fatalf("ingress error: %v", err)
	default:
	}
}

func assertPersistedPublication(t *testing.T, database *sql.DB, routeID string, wantJobs int) {
	t.Helper()
	var leaseStatus, jobState string
	if err := database.QueryRow(`SELECT status FROM route_leases WHERE route_id = ? ORDER BY generation DESC LIMIT 1`, routeID).Scan(&leaseStatus); err != nil {
		t.Fatal(err)
	}
	if leaseStatus != "ready" {
		t.Fatalf("lease status = %q", leaseStatus)
	}
	var installedAt, challengeRemovedAt sql.NullInt64
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := database.QueryRow(`SELECT state, installed_at, challenge_removed_at FROM certificate_jobs WHERE route_id = ? ORDER BY generation DESC LIMIT 1`, routeID).Scan(
			&jobState, &installedAt, &challengeRemovedAt,
		); err != nil {
			t.Fatal(err)
		}
		if jobState == certificates.StateSucceeded && installedAt.Valid && challengeRemovedAt.Valid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("certificate job = %q, installed = %v, challenge removed = %v", jobState, installedAt.Valid, challengeRemovedAt.Valid)
		}
		time.Sleep(10 * time.Millisecond)
	}
	var jobs int
	if err := database.QueryRow(`SELECT COUNT(*) FROM certificate_jobs WHERE route_id = ?`, routeID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != wantJobs {
		t.Fatalf("certificate jobs = %d, want %d", jobs, wantJobs)
	}
	var accountKID string
	if err := database.QueryRow(`SELECT kid FROM acme_accounts LIMIT 1`).Scan(&accountKID); err != nil {
		t.Fatal(err)
	}
	if accountKID == "" {
		t.Fatal("ACME account KID was not persisted")
	}
}

type integrationPublication struct {
	cancel  context.CancelFunc
	done    chan error
	ready   chan string
	stopped bool
}

func startIntegrationPublication(ctx context.Context, config PublicConfig) *integrationPublication {
	publicationContext, cancel := context.WithCancel(ctx)
	run := &integrationPublication{cancel: cancel, done: make(chan error, 1), ready: make(chan string, 1)}
	config.OnReady = func(publicURL string) { run.ready <- publicURL }
	go func() { run.done <- RunPublic(publicationContext, config) }()
	return run
}

func (p *integrationPublication) WaitReady(t *testing.T, ctx context.Context, hostname string, pebble *integrationtest.Pebble) {
	t.Helper()
	select {
	case publicURL := <-p.ready:
		if publicURL != "https://"+hostname {
			t.Fatalf("public URL = %q", publicURL)
		}
	case err := <-p.done:
		p.stopped = true
		t.Fatalf("publication stopped before readiness: %v; Pebble logs:\n%s", err, pebble.Logs())
	case <-ctx.Done():
		t.Fatalf("wait for publication: %v; Pebble logs:\n%s", ctx.Err(), pebble.Logs())
	}
}

func (p *integrationPublication) Stop(t *testing.T) {
	t.Helper()
	if p.stopped {
		return
	}
	p.cancel()
	if err := <-p.done; err != nil {
		t.Errorf("stop publication: %v", err)
	}
	p.stopped = true
}

func readCurrentMaterial(t *testing.T, store *clientstate.Store, routeID, hostname string) clientstate.Material {
	t.Helper()
	routeState, err := store.OpenRoute(routeID)
	if err != nil {
		t.Fatal(err)
	}
	material, found, currentErr := routeState.Current(hostname)
	closeErr := routeState.Close()
	if currentErr != nil || closeErr != nil || !found || !material.Installed {
		t.Fatalf("agent certificate = %+v, found = %v, error = %v", material, found, errors.Join(currentErr, closeErr))
	}
	return material
}

func forceRenewalDue(
	t *testing.T,
	database *sql.DB,
	stateRoot, serverOrigin, routeID, orderID string,
	due time.Time,
) {
	t.Helper()
	digest := sha256.Sum256([]byte(serverOrigin))
	currentPath := filepath.Join(
		stateRoot, "servers", hex.EncodeToString(digest[:]), "routes", routeID, "current.json",
	)
	contents, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	var current map[string]json.RawMessage
	if err := json.Unmarshal(contents, &current); err != nil {
		t.Fatal(err)
	}
	current["renew_at"], err = json.Marshal(due)
	if err != nil {
		t.Fatal(err)
	}
	contents, err = json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(currentPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := database.Exec(`UPDATE certificate_jobs SET renew_at = ? WHERE id = ? AND route_id = ?`, due.Unix(), orderID, routeID)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		t.Fatalf("force renewal rows = %d, error = %v", changed, err)
	}
}
