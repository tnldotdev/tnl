package daemon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	wasmfixture "github.com/tnldotdev/tnl/development/connector-wasm/fixture"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var wasmFixtureFile = flag.String("tnl-wasm-fixture-file", "", "private local qualification configuration")
var wasmFixtureDuration = flag.Duration("tnl-wasm-fixture-duration", 8*time.Minute, "maximum ready-fixture lifetime")
var wasmFixtureCommand = flag.String("tnl-wasm-fixture-command", "", "optional qualification command JSON argv")
var wasmFixtureSelfTest = flag.Bool("tnl-wasm-fixture-self-test", false, "native retained-session proof")

// this qualification composes the existing daemon fixture, not a second topology
// engine. real control, relay, publisher and workload authority code runs.
func TestIntegrationConnectorWASMFixture(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectorWASMFixture(t)
}

func TestLoadConnectorWASMFixture(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierRuntimeLoad)
	runConnectorWASMFixture(t)
}

func runConnectorWASMFixture(t *testing.T) {
	t.Helper()
	if *wasmFixtureCommand == "" && *wasmFixtureFile == "" && !*wasmFixtureSelfTest {
		t.Skip("requires -tnl-wasm-fixture-command, -tnl-wasm-fixture-file, or -tnl-wasm-fixture-self-test")
	}
	if *wasmFixtureDuration < time.Second || *wasmFixtureDuration > 20*time.Minute {
		t.Fatal("-tnl-wasm-fixture-duration must be between 1s and 20m")
	}
	var argv []string
	if *wasmFixtureCommand != "" {
		if err := json.Unmarshal([]byte(*wasmFixtureCommand), &argv); err != nil || len(argv) == 0 || argv[0] == "" {
			t.Fatal("-tnl-wasm-fixture-command requires a nonempty JSON argument array")
		}
		if *wasmFixtureSelfTest {
			t.Fatal("choose a qualification subprocess or the native self-test, not both")
		}
	}
	fixtureFile := *wasmFixtureFile
	if fixtureFile == "" {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		fixtureFile = filepath.Join(directory, "fixture.json")
	}
	if err := wasmfixture.ValidateFile(fixtureFile); err != nil {
		t.Fatal(err)
	}
	lifetime, stop := signal.NotifyContext(t.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	f, issuer := newWorkloadTransportFixture(t, nil)
	application, applicationURL := wasmApplicationDatabase(t, f)
	group, protocol := "private", controlv1.Postgres
	policies := map[string]controlv1.ProjectWorkload{"qualification": {
		Provider: controlv1.WorkloadGitHub,
		Github:   &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}},
		Services: []string{"db"}, MaxDurationSeconds: 0,
	}}
	fingerprint := strings.Repeat("a", 64)
	applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{
		TeamId: f.identity.teamID, SourceFingerprint: fingerprint,
		Configuration: controlv1.ProjectConfiguration{Workloads: &policies, PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {}},
			Services: map[string]controlv1.ProjectServiceConfiguration{"db": {PublisherGroup: &group, Protocol: &protocol, Target: net.JoinHostPort(application.Host, strconv.Itoa(int(application.Port)))}},
			Webhooks: map[string]controlv1.ProjectWebhook{}},
	})
	if err != nil || len(applied.Services) != 1 || applied.Services[0].ServiceId == nil {
		t.Fatal("apply qualification service", err)
	}
	serviceID := *applied.Services[0].ServiceId
	// publisher connections use the real relay addresses. connector-only proxies
	// below interrupt outer carriers without killing the target application.
	startWorkloadPublishers(t, f, group, "tls-tcp")
	proxies := make(map[string]*wasmCarrierProxy)
	connectorFixture := *f
	connectorFixture.tcpAddresses = make(map[string]string)
	for address := range f.tcpAddresses {
		proxy := newWASMCarrierProxy(t, address)
		proxies[address] = proxy
		connectorFixture.tcpAddresses[address] = proxy.listener.Addr().String()
	}
	job, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
	if err != nil {
		t.Fatal(err)
	}
	claims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
	claims["check_run_id"], claims["jti"] = wasmExecutionID("native-baseline"), "native-baseline"
	session, err := job.Exchange(t.Context(), f.identity.teamID, "workload", fingerprint, "qualification", issuer.Sign(t, claims), []string{"db"})
	if err != nil {
		t.Fatal("exchange native workload", err)
	}
	renewed, err := job.Renew(t.Context())
	if err != nil || renewed.Id != session.Id || renewed.RenewalSequence != session.RenewalSequence+1 {
		t.Fatal("signed native workload renewal changed authority or did not advance its sequence", err)
	}
	session = renewed
	renewRuntimeWorkload(t, job, nil)
	refreshWASMNativeAssertion(t, f, issuer, job)
	control, err := connectorstream.NewWorkloadControl(job)
	if err != nil {
		t.Fatal(err)
	}
	run, err := control.ResolveService(t.Context(), serviceID)
	if err != nil {
		t.Fatal(err)
	}
	if run.PairReady == nil || len(run.PairReady.Relays) != 2 {
		t.Fatal("native service selection did not contain two ready relays")
	}
	listener := serviceRuntimeListener(t)
	connectorContext, cancelConnector := context.WithCancel(t.Context())
	ready, done := make(chan struct{}), make(chan error, 1)
	_, tcp := connectorFixture.connectors()
	go func() {
		done <- connectorstream.Serve(connectorContext, listener, connectorstream.Config{Control: control, ServiceID: serviceID, Protocol: run.Protocol,
			TrustRevision: run.TrustRevision, Endpoint: run.Endpoint, ServiceTLS: f.visitorRoots, TransportTLS: f.roots,
			RelayQUIC: privateDisabledConnector(), RelayTCP: tcp, Ready: func() error { close(ready); return nil }})
	}()
	t.Cleanup(func() {
		cancelConnector()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("native connector shutdown: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("native connector did not join")
		}
	})
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal("native connector startup", err)
	case <-time.After(35 * time.Second):
		t.Fatal("native connector readiness exceeded its existing setup bound")
	}
	// readiness includes a real application-authenticated postgresql query.
	nativePG := application.Copy()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := strconv.Atoi(port)
	nativePG.Host, nativePG.Port, nativePG.Fallbacks = host, uint16(number), nil
	nativePG.TLSConfig = f.visitorRoots.Clone()
	nativePG.TLSConfig.ServerName = run.Endpoint.Hostname
	nativePG.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	setup, setupCancel := context.WithTimeout(t.Context(), 5*time.Second)
	connection, err := pgx.ConnectConfig(setup, nativePG)
	setupCancel()
	if err != nil {
		t.Fatal("native PostgreSQL readiness", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = connection.Close(ctx)
	})
	var nativePID int
	query, queryCancel := context.WithTimeout(t.Context(), 5*time.Second)
	err = connection.QueryRow(query, "SELECT pg_backend_pid()").Scan(&nativePID)
	queryCancel()
	if err != nil {
		t.Fatal("native PostgreSQL query readiness", err)
	}

	token := wasmRandomSecret(t)
	shutdown := make(chan struct{})
	var shutOnce sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("POST /shutdown", func(w http.ResponseWriter, _ *http.Request) {
		shutOnce.Do(func() { close(shutdown) })
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /fault/relay", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RelayAddress string `json:"relay_address"`
			Blocked      *bool  `json:"blocked"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || body.Blocked == nil || proxies[body.RelayAddress] == nil {
			http.Error(w, "requires known relay_address and blocked", http.StatusBadRequest)
			return
		}
		closed := proxies[body.RelayAddress].setBlocked(*body.Blocked)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"relay_address": body.RelayAddress, "blocked": *body.Blocked, "closed_connections": closed, "boundary": "connector_outer_tls_tcp_carrier"})
	})
	mux.HandleFunc("GET /assertion", func(w http.ResponseWriter, r *http.Request) {
		execution := r.URL.Query().Get("execution")
		if len(execution) < 1 || len(execution) > 80 || strings.ContainsAny(execution, "\r\n\x00") {
			http.Error(w, "requires execution (1-80 characters)", http.StatusBadRequest)
			return
		}
		now := time.Now()
		claims := githubtest.Claims(f.controlConfig.ControlOrigin(), now)
		claims["check_run_id"], claims["jti"] = wasmExecutionID(execution), wasmRandomSecret(t)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"token": issuer.Sign(t, claims), "expires_at": now.Add(5 * time.Minute)})
	})
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// httptest binds 127.0.0.1; a private per-run bearer also blocks ambient
		// browser requests and other local users from obtaining assertions.
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "fixture authentication required", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	api.Config.ReadTimeout, api.Config.WriteTimeout = 5*time.Second, 5*time.Second
	api.Start()
	t.Cleanup(func() { api.CloseClientConnections(); api.Close() })
	relays := make([]wasmfixture.Relay, 0, 2)
	for _, relay := range run.PairReady.Relays {
		relays = append(relays, wasmfixture.Relay{RelayAddress: relay.RelayAddress, DialAddress: proxies[relay.RelayAddress].listener.Addr().String(), TLSServerName: relay.TlsServerName})
	}
	descriptor := wasmfixture.Config{
		Version: 1, ControlURL: f.controlConfig.ControlOrigin(), ControlDialAddress: f.publicControlAddress,
		ControlRootPEM: string(f.certificateAuthority.certificatePEM), RelayRootPEM: string(f.certificateAuthority.certificatePEM), ServiceRootPEM: string(f.visitorRootPEM),
		TeamID: f.identity.teamID, Project: "workload", SourceFingerprint: fingerprint, WorkloadPolicy: "qualification", Services: map[string]string{"db": serviceID},
		ServiceEndpoint: *run.Endpoint, Relays: relays, OuterTransport: "tls-tcp", FixtureAPIURL: api.URL, FixtureAPIToken: token,
		AssertionURL: api.URL + "/assertion", FaultURL: api.URL + "/fault/relay", ShutdownURL: api.URL + "/shutdown",
		NativeConnectorAddress: listener.Addr().String(), NativeWorkloadSessionID: session.Id,
		Postgres: wasmfixture.Postgres{User: application.User, Password: application.Password, Database: application.Database, DirectURL: applicationURL, TLSServerName: run.Endpoint.Hostname,
			WriteTable: "public.connector_wasm_writes", WriteIDColumn: "id"},
		FaultScope: "connector outer carriers only; publisher connections and the PostgreSQL target remain live",
	}
	if err := descriptor.WriteFile(fixtureFile); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(fixtureFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error(err)
		}
	})
	t.Log("local connector fixture ready; credentials are only in the requested private file")
	if *wasmFixtureSelfTest {
		wasmNativeProof(t, f, session.Id, proxies, connection, application, nativePID)
		return
	}
	ctx, cancel := context.WithTimeout(lifetime, *wasmFixtureDuration)
	defer cancel()
	if *wasmFixtureCommand != "" {
		for i := range argv {
			argv[i] = strings.ReplaceAll(argv[i], "{fixture}", fixtureFile)
		}
		command := exec.Command(argv[0], argv[1:]...)
		command.Dir = integrationRepositoryRoot(t)
		command.Stdout, command.Stderr, command.Stdin = os.Stdout, os.Stderr, os.Stdin
		// reuse the runtime test harness's owned subprocess and descendant cleanup.
		finish := isolateIntegrationDNSProcess(t, command)
		owner, err := startOwnedCommand(command, finish)
		if err != nil {
			t.Fatal("start local qualification command", err)
		}
		t.Cleanup(func() {
			if err := owner.shutdown(5*time.Second, 5*time.Second); err != nil {
				t.Error("qualification command shutdown", err)
			}
		})
		select {
		case <-owner.done:
			if err := owner.result(); err != nil {
				t.Fatal("local qualification command", err)
			}
			var sessions, keys, renewed, revoked int
			if err := f.inspect.QueryRowContext(t.Context(), `
				SELECT count(*), count(DISTINCT public_key), count(*) FILTER (WHERE renewal_sequence > 0),
				       count(*) FILTER (WHERE revoked_at IS NOT NULL)
				FROM control.workload_sessions
				WHERE team_id=$1 AND project_key='workload'
				  AND workload_name='qualification' AND id<>$2`, f.identity.teamID, session.Id).
				Scan(&sessions, &keys, &renewed, &revoked); err != nil {
				t.Fatal("observe qualification workload lifetimes", err)
			}
			if sessions < 1 || keys != sessions || renewed != sessions || revoked != sessions {
				t.Fatalf("qualification workload lifetimes: sessions=%d keys=%d renewed=%d revoked=%d", sessions, keys, renewed, revoked)
			}
			t.Logf("qualification workload lifetimes: %d independently exchanged, renewed, and revoked", sessions)
		case <-ctx.Done():
			t.Fatal("qualification command exceeded fixture lifetime or was interrupted", ctx.Err())
		}
		return
	}
	select {
	case <-shutdown:
	case <-lifetime.Done():
	case <-ctx.Done():
		t.Fatal("fixture lifetime reached without a qualification command or explicit shutdown")
	}
}

func wasmRandomSecret(t *testing.T) string {
	t.Helper()
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(secret[:])
}

func wasmExecutionID(label string) string {
	digest := sha256.Sum256([]byte(label))
	return strconv.FormatUint((binary.BigEndian.Uint64(digest[:8])>>1)+1, 10)
}

func wasmApplicationDatabase(t *testing.T, f *privateSeparatedFixture) (*pgx.ConnConfig, string) {
	t.Helper()
	role := "wasm_" + wasmExecutionID(wasmRandomSecret(t))
	password := wasmRandomSecret(t)
	created := false
	// registered before the database cleanup so role dependencies are gone first.
	t.Cleanup(func() {
		if !created {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := f.inspect.ExecContext(ctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Error("drop application role", err)
		}
	})
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "connector-wasm-app")
	admin, err := pgx.Connect(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer closeWASMPostgres(t, admin)
	// random passwords use only base64url characters, never sql punctuation.
	if _, err := admin.Exec(t.Context(), "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN PASSWORD '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	created = true
	if _, err := admin.Exec(t.Context(), "CREATE TABLE public.connector_wasm_writes (id text PRIMARY KEY, value integer NOT NULL); GRANT USAGE ON SCHEMA public TO "+pgx.Identifier{role}.Sanitize()+"; GRANT SELECT, INSERT ON public.connector_wasm_writes TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.User, config.Password = role, password
	applicationURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	applicationURL.User = url.UserPassword(role, password)
	return config, applicationURL.String()
}

func refreshWASMNativeAssertion(t *testing.T, f *privateSeparatedFixture, issuer *githubtest.Issuer, job *workload.Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- nil
				return
			case <-ticker.C:
				claims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
				claims["check_run_id"], claims["jti"] = wasmExecutionID("native-baseline"), wasmRandomSecret(t)
				if _, err := job.Attach(ctx, issuer.Sign(t, claims)); err != nil {
					if ctx.Err() != nil {
						err = nil
					}
					done <- err
					return
				}
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("refresh native platform assertion", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("native platform assertion refresh did not join")
		}
	})
}

func wasmNativeProof(t *testing.T, f *privateSeparatedFixture, source string, proxies map[string]*wasmCarrierProxy, connection *pgx.Conn, application *pgx.ConnConfig, pid int) {
	t.Helper()
	setup, finishSetup := context.WithTimeout(t.Context(), 5*time.Second)
	defer finishSetup()
	observer, err := pgx.ConnectConfig(setup, application)
	if err != nil {
		t.Fatal("open independent native write observer", err)
	}
	defer closeWASMPostgres(t, observer)
	tx, err := connection.Begin(setup)
	if err != nil {
		t.Fatal("begin native transaction before interruption", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("rollback unfinished native proof transaction", err)
		}
	}()
	id := "native-carrier-proof-" + wasmRandomSecret(t)
	if _, err := tx.Exec(setup, "INSERT INTO public.connector_wasm_writes(id,value) VALUES ($1,42)", id); err != nil {
		t.Fatal("insert native write before interruption", err)
	}
	var count int
	if err := observer.QueryRow(setup, "SELECT count(*) FROM public.connector_wasm_writes WHERE id=$1", id).Scan(&count); err != nil || count != 0 {
		t.Fatal("independent observer saw the uncommitted native write", err)
	}
	var address string
	if err := f.inspect.QueryRowContext(setup, "SELECT slots->0->>'relay_address' FROM control.connector_peer_pairs WHERE subject_kind='workload_session' AND subject_id=$1", source).Scan(&address); err != nil {
		t.Fatal(err)
	}
	proxy := proxies[address]
	if proxy == nil {
		t.Fatal("active native relay carrier proxy was not found")
	}
	// restore the carrier before the deferred rollback if an assertion fails.
	defer proxy.setBlocked(false)
	if proxy.setBlocked(true) < 1 {
		t.Fatal("active native relay carrier was not interrupted")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var after, value int
	if err := tx.QueryRow(ctx, "SELECT pg_backend_pid(),value FROM public.connector_wasm_writes WHERE id=$1", id).Scan(&after, &value); err != nil || after != pid || value != 42 {
		t.Fatal("carrier interruption replaced the PostgreSQL session or lost its open transaction", err)
	}
	if err := observer.QueryRow(ctx, "SELECT count(*) FROM public.connector_wasm_writes WHERE id=$1", id).Scan(&count); err != nil || count != 0 {
		t.Fatal("native write committed before the explicit post-interruption commit", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit retained native transaction after interruption", err)
	}
	if err := observer.QueryRow(ctx, "SELECT count(*) FROM public.connector_wasm_writes WHERE id=$1 AND value=42", id).Scan(&count); err != nil || count != 1 {
		t.Fatal("native write was not committed exactly once", err)
	}
	t.Logf("native proof: open transaction retained PostgreSQL backend PID %d across interrupted active relay carrier; independent observer saw exactly one committed write", pid)
}

func closeWASMPostgres(t *testing.T, connection *pgx.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := connection.Close(ctx); err != nil {
		t.Error("close fixture PostgreSQL connection", err)
	}
}

type wasmCarrierProxy struct {
	listener    net.Listener
	target      string
	mu          sync.Mutex
	blocked     bool
	connections map[net.Conn]net.Conn
	workers     sync.WaitGroup
}

func newWASMCarrierProxy(t *testing.T, target string) *wasmCarrierProxy {
	t.Helper()
	listener := serviceRuntimeListener(t)
	p := &wasmCarrierProxy{listener: listener, target: target, connections: make(map[net.Conn]net.Conn)}
	t.Cleanup(func() {
		_ = listener.Close()
		p.setBlocked(true)
		done := make(chan struct{})
		go func() { p.workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("connector carrier proxy did not join")
		}
	})
	p.workers.Go(func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			p.workers.Go(func() { p.forward(connection) })
		}
	})
	return p
}

func (p *wasmCarrierProxy) setBlocked(blocked bool) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blocked = blocked
	if !blocked {
		return 0
	}
	closed := 0
	for incoming, outgoing := range p.connections {
		_ = incoming.Close()
		_ = outgoing.Close()
		closed++
	}
	return closed
}

func (p *wasmCarrierProxy) forward(incoming net.Conn) {
	defer incoming.Close()
	p.mu.Lock()
	blocked := p.blocked
	p.mu.Unlock()
	if blocked {
		return
	}
	outgoing, err := net.DialTimeout("tcp", p.target, time.Second)
	if err != nil {
		return
	}
	defer outgoing.Close()
	p.mu.Lock()
	if p.blocked {
		p.mu.Unlock()
		return
	}
	p.connections[incoming] = outgoing
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.connections, incoming); p.mu.Unlock() }()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(incoming, outgoing); _ = incoming.Close(); _ = outgoing.Close(); close(done) }()
	_, _ = io.Copy(outgoing, incoming)
	_ = incoming.Close()
	_ = outgoing.Close()
	<-done
}

func TestWASMCarrierProxyBlocksAndRestores(t *testing.T) {
	target := startPrivateEchoTarget(t)
	proxy := newWASMCarrierProxy(t, target.address)
	dial := func() net.Conn {
		t.Helper()
		connection, err := net.DialTimeout("tcp", proxy.listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connection.Close() })
		if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		return connection
	}
	exchange := func(connection net.Conn, message string) {
		t.Helper()
		if _, err := io.WriteString(connection, message); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(message))
		if _, err := io.ReadFull(connection, got); err != nil || string(got) != message {
			t.Fatal("proxy exchange", err)
		}
	}
	connection := dial()
	exchange(connection, "before-cut\n")
	if proxy.setBlocked(true) != 1 {
		t.Fatal("proxy did not close the established carrier")
	}
	var one [1]byte
	if _, err := connection.Read(one[:]); err == nil {
		t.Fatal("cut carrier remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("cut carrier did not close promptly")
	}
	blocked := dial()
	if _, err := blocked.Read(one[:]); err == nil {
		t.Fatal("blocked carrier remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("proxy did not reject a new blocked carrier")
	}
	proxy.setBlocked(false)
	exchange(dial(), "after-restore\n")
}
