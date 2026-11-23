package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/client/auth"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var (
	wasmFixtureFile     = flag.String("tnl-wasm-fixture-file", "", "private portable SDK fixture descriptor")
	wasmFixtureCommand  = flag.String("tnl-wasm-fixture-command", "", "portable SDK runner JSON argv; {fixture} expands to the descriptor")
	wasmFixtureDuration = flag.Duration("tnl-wasm-fixture-duration", 5*time.Minute, "maximum portable SDK fixture lifetime")
	wasmMySQLURL        = flag.String("tnl-wasm-mysql-url", "", "Task-owned disposable MySQL application URL")
	wasmMySQLCA         = flag.String("tnl-wasm-mysql-ca-file", "", "optional disposable MySQL target CA file")
	wasmMySQLHostname   = flag.String("tnl-wasm-mysql-tls-hostname", "", "optional disposable MySQL target TLS hostname")
	wasmRedisAddress    = flag.String("tnl-test-redis-address", "", "Task-owned disposable Redis application address")
)

type wasmFixtureRelay struct {
	Address       string `json:"address"`
	DialAddress   string `json:"dial_address"`
	TLSServerName string `json:"tls_server_name"`
}

type wasmFixtureCredentials struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
}

// this private descriptor contains credentials, never browser-safe project metadata.
type wasmFixtureDescriptor struct {
	Version            int                                  `json:"version"`
	Project            string                               `json:"project"`
	Deployment         string                               `json:"deployment"`
	Token              string                               `json:"token"`
	ControlURL         string                               `json:"control_url"`
	ControlDialAddress string                               `json:"control_dial_address"`
	ControlRootPEM     string                               `json:"control_root_pem"`
	RelayRootPEM       string                               `json:"relay_root_pem"`
	ServiceRootPEM     string                               `json:"service_root_pem"`
	Services           map[string]string                    `json:"services"`
	Endpoints          map[string]controlv1.ServiceEndpoint `json:"endpoints"`
	Relays             []wasmFixtureRelay                   `json:"relays"`
	SPKIPins           []string                             `json:"spki_pins"`
	APIURL             string                               `json:"api_url"`
	APIToken           string                               `json:"api_token"`
	Postgres           wasmFixtureCredentials               `json:"postgres"`
	MySQL              wasmFixtureCredentials               `json:"mysql"`
	RedisPassword      string                               `json:"redis_password"`
	KubernetesToken    string                               `json:"kubernetes_token"`
	SourceFingerprint  string                               `json:"source_fingerprint"`
}

// reuse the separated daemon fixture and native publication owner. this test
// adds only target listeners, a private runner API, and connector carrier faults.
func TestIntegrationConnectorWASMFixture(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *wasmFixtureCommand == "" && *wasmFixtureFile == "" {
		t.Skip("requires -tnl-wasm-fixture-command or -tnl-wasm-fixture-file")
	}
	if *wasmFixtureDuration < time.Second || *wasmFixtureDuration > 20*time.Minute {
		t.Fatal("-tnl-wasm-fixture-duration must be between 1s and 20m")
	}
	var argv []string
	if *wasmFixtureCommand != "" {
		if err := json.Unmarshal([]byte(*wasmFixtureCommand), &argv); err != nil || len(argv) == 0 || argv[0] == "" {
			t.Fatal("-tnl-wasm-fixture-command requires a nonempty JSON argument array")
		}
	}
	file := *wasmFixtureFile
	if file == "" {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal("protect fixture descriptor directory", err)
		}
		file = filepath.Join(directory, "fixture.json")
	}
	if err := validateWASMFixturePath(file); err != nil {
		t.Fatal(err)
	}
	mySQLTarget, mySQLCredentials, mySQLTrust := wasmMySQLTarget(t)
	if host, _, err := net.SplitHostPort(*wasmRedisAddress); err != nil || (host != "localhost" && !net.ParseIP(host).IsLoopback()) {
		t.Fatal("portable SDK fixture requires a loopback Redis fixture")
	}
	f, issuer := newWorkloadTransportFixture(t)
	proxies, relays, pins := wasmFixtureRelays(t, f)
	pgConfig, observer := wasmPostgresTarget(t, f)
	tcpTarget := startPrivateEchoTarget(t, f.owner)
	httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Tnl-Access-Token") != "" || r.Header.Get("Tnl-Visitor-Token") != "" {
			http.Error(w, "tnl credential reached target", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"method": r.Method, "path": r.URL.RequestURI(), "fixture": "portable-sdk"})
	}))
	cleanupIntegrationHTTPServer(t, httpTarget, f.owner)
	clusterToken := wasmFixtureSecret(t)
	cluster := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+clusterToken)) != 1 {
			http.Error(w, "cluster authentication required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/namespaces/portable/pods" {
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "PodList", "items": []any{map[string]any{"metadata": map[string]string{"name": "portable-fixture"}}}})
			return
		}
		http.NotFound(w, r)
	}))
	const clusterHostname = "cluster.private.integration.test"
	cluster.TLS = serviceRuntimeTLS(t, f.certificateAuthority, clusterHostname)
	cluster.StartTLS()
	cleanupIntegrationHTTPServer(t, cluster, f.owner)
	deployment := "portable"
	declarations := controlv1.ProjectServiceDeclarations{"http": "http", "tcp": "tcp", "postgres": "postgres", "mysql": "mysql", "kubernetes": "kubernetes", "redis": "tcp"}
	configuration := controlv1.ProjectConfiguration{Settings: &controlv1.DeploymentSettings{}, Services: map[string]controlv1.ProjectServiceConfiguration{}, Webhooks: map[string]controlv1.ProjectWebhook{}}
	configuration.Workloads = new(map[string]controlv1.ProjectWorkload{
		"portable-reader": {
			Deployment: deployment, Provider: controlv1.WorkloadGitHub,
			Github: &controlv1.ProjectWorkloadGitHub{
				Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789",
				WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"},
			},
			Services: []string{"http"}, MaxDurationSeconds: 90,
		},
	})
	targets := map[string]string{
		"http": strings.TrimPrefix(httpTarget.URL, "http://"), "tcp": tcpTarget.address,
		"postgres": net.JoinHostPort(pgConfig.Host, strconv.Itoa(int(pgConfig.Port))),
		"mysql":    mySQLTarget, "kubernetes": strings.TrimPrefix(cluster.URL, "https://"), "redis": *wasmRedisAddress,
	}
	for name, protocol := range declarations {
		service := controlv1.ProjectServiceConfiguration{Protocol: new(protocol), Target: targets[name], Public: new(false)}
		if name == "kubernetes" {
			trust := serviceHTTPTestTargetTrust(clusterHostname, string(f.certificateAuthority.certificatePEM))
			service.TargetTls = &trust
		} else if name == "mysql" {
			service.TargetTls = mySQLTrust
		}
		configuration.Services[name] = service
	}
	applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{
		Deployment: deployment, ServiceDeclarations: declarations, TeamId: f.identity.teamID, Source: &testProjectSource, Configuration: configuration,
	})
	if err != nil || applied.Deployments == nil || len(*applied.Deployments) != 1 {
		t.Fatal("apply portable SDK fixture services", err)
	}
	services, endpoints := make(map[string]string), make(map[string]controlv1.ServiceEndpoint)
	for _, service := range applied.Services {
		if service.ServiceId == nil {
			t.Fatal("fixture service has no saved service ID")
		}
		services[service.Service] = *service.ServiceId
	}
	if len(services) != len(declarations) {
		t.Fatal("fixture did not save all services")
	}
	// publisher sockets use real relay addresses. only connectors use the fault
	// proxies in the descriptor; a fault cannot replace the native publication.
	startWorkloadPublishers(t, f, deployment, "wss")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	selection := controlv1.DeploymentCredentialServiceSelection{"http", "tcp", "postgres", "mysql", "kubernetes", "redis"}
	request := controlv1.RegisterDeploymentCredentialRequest{Name: "portable-sdk", PublicKey: base64.RawURLEncoding.EncodeToString(public), ExpiresIn: 1200, DeploymentIds: new([]string{(*applied.Deployments)[0].Id})}
	request.Permissions.Connect = &selection
	approval, err := f.identity.routes.RegisterDeploymentCredential(t.Context(), f.identity.teamID, "workload", "portable-sdk", request)
	if err != nil {
		t.Fatal("register portable SDK credential", err)
	}
	team, err := f.identity.authority.GetTeam(t.Context(), f.identity.teamID)
	if err != nil {
		t.Fatal(err)
	}
	teamName := team.DisplayName
	if teamName == "" {
		t.Fatal("fixture personal team is missing")
	}
	token, err := (auth.DeploymentCredential{Version: 1, ControlURL: f.controlConfig.ControlOrigin(), Team: teamName, Approval: approval, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range services {
		service, err := f.identity.routes.GetService(t.Context(), id)
		if err != nil || service.Endpoint == nil || service.Endpoint.Public {
			t.Fatal("fixture must remain connector-only", err)
		}
		endpoints[name] = *service.Endpoint
	}
	apiToken := wasmFixtureSecret(t)
	stopped := make(chan struct{})
	api := wasmFixtureAPI(t, f, apiToken, stopped, proxies, observer, services["postgres"], issuer)
	descriptor := wasmFixtureDescriptor{
		Version: 1, Project: teamName + "/workload", Deployment: deployment, Token: token,
		ControlURL: f.controlConfig.ControlOrigin(), ControlDialAddress: f.publicControlAddress,
		ControlRootPEM: string(f.certificateAuthority.certificatePEM), RelayRootPEM: string(f.certificateAuthority.certificatePEM), ServiceRootPEM: string(f.visitorRootPEM),
		Services: services, Endpoints: endpoints, Relays: relays, SPKIPins: pins, APIURL: api.URL, APIToken: apiToken,
		Postgres: wasmFixtureCredentials{User: pgConfig.User, Password: pgConfig.Password, Database: pgConfig.Database},
		MySQL:    mySQLCredentials, KubernetesToken: clusterToken, RedisPassword: "testpass", SourceFingerprint: applied.SourceFingerprint,
	}
	bytes, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("create private fixture file", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error("remove private fixture file", err)
		}
	})
	_, writeErr := output.Write(bytes)
	if err := errors.Join(writeErr, output.Close()); err != nil {
		t.Fatal("write private fixture file", err)
	}
	t.Log("portable SDK fixture ready; credentials are only in its private descriptor")
	lifetime, stop := signal.NotifyContext(t.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(lifetime, *wasmFixtureDuration)
	defer cancel()
	if len(argv) == 0 {
		select {
		case <-stopped:
		case <-ctx.Done():
			t.Fatal("fixture ended without explicit shutdown", ctx.Err())
		}
		return
	}
	for i := range argv {
		argv[i] = strings.ReplaceAll(argv[i], "{fixture}", file)
	}
	command := exec.Command(argv[0], argv[1:]...)
	command.Dir = integrationRepositoryRoot(t)
	command.Stdout, command.Stderr, command.Stdin = os.Stdout, os.Stderr, os.Stdin
	finish := isolateIntegrationCommand(t, command)
	owner, err := startOwnedCommand(command, finish)
	if err != nil {
		t.Fatal("start portable SDK runner", err)
	}
	t.Cleanup(func() {
		if err := owner.shutdown(5*time.Second, 5*time.Second); err != nil {
			t.Error("portable SDK runner cleanup", err)
		}
	})
	select {
	case <-owner.done:
		if err := owner.result(); err != nil {
			t.Fatal("portable SDK runner", err)
		}
	case <-ctx.Done():
		t.Fatal("portable SDK runner exceeded fixture lifetime", ctx.Err())
	}
}

func wasmFixtureRelays(t *testing.T, f *privateSeparatedFixture) (map[string]*wasmCarrierProxy, []wasmFixtureRelay, []string) {
	t.Helper()
	// native fixtures allow an independent dial address and tls hostname. browser
	// WebSocket requires one real hostname, so replace the initial two relays
	// before starting publishers. their old leases must actually retire first.
	for _, relay := range f.relayProcesses {
		if err := relay.stop(); err != nil {
			t.Fatal("stop initial native fixture relay", err)
		}
	}
	privateWait(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		var count int
		err := f.inspect.QueryRowContext(ctx, "SELECT count(*) FROM control.relay_leases WHERE lease_expires_at>now() AND NOT draining").Scan(&count)
		return count == 0, err
	})
	f.relayProcesses = make(map[string]*privateRelayFixture)
	f.tcpAddresses, f.quicAddresses = make(map[string]string), make(map[string]string)
	proxies := make(map[string]*wasmCarrierProxy)
	var relays []wasmFixtureRelay
	var pins []string
	for index := range 2 {
		listener, packets := fixtureRelaySockets(t, f.owner)
		proxy := newWASMCarrierProxy(t, f.owner, listener.Addr().String())
		_, port, err := net.SplitHostPort(proxy.listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		address := net.JoinHostPort("localhost", port)
		id := fmt.Sprintf("portable-relay-%d", index)
		internal, forwarding := fixtureRelaySockets(t, f.owner)
		settings := relayProcessSettings{
			controlEndpoint: f.controlConfig.PrivateControlEndpoint(), controlAddress: f.controlConfig.PrivateControlListen, clusterSecret: serviceRuntimeClusterSecret,
			relayServiceID: id, relayID: id, relayAddress: address, tlsServerName: "localhost", transportTLS: serviceRuntimeTLS(t, f.certificateAuthority, "localhost"),
			internalListener: internal, internalPacket: forwarding, internalAddress: internal.Addr().String(), tcpListener: listener, udpPacket: packets, udpListen: packets.LocalAddr().String(),
			quic: f.controlConfig.RelayQUICConfig(), runtime: relaySettingsFrom(f.controlConfig),
		}
		f.runFixtureRelay(t, settings)
		proxies[address] = proxy
		relays = append(relays, wasmFixtureRelay{Address: address, DialAddress: proxy.listener.Addr().String(), TLSServerName: "localhost"})
		leaf, err := x509.ParseCertificate(settings.transportTLS.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		pins = append(pins, base64.StdEncoding.EncodeToString(digest[:]))
	}
	control := f.roots.Clone()
	control.ServerName = strings.TrimPrefix(f.controlConfig.ControlOrigin(), "https://")
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", f.publicControlAddress, control)
	if err != nil {
		t.Fatal("observe fixture control leaf pin", err)
	}
	digest := sha256.Sum256(connection.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo)
	pins = append(pins, base64.StdEncoding.EncodeToString(digest[:]))
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	sort.Slice(relays, func(i, j int) bool { return relays[i].Address < relays[j].Address })
	sort.Strings(pins)
	return proxies, relays, pins
}

func validateWASMFixturePath(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("-tnl-wasm-fixture-file must be absolute")
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return errors.New("fixture file requires an existing private directory (mode 0700)")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixture file must not already exist")
	}
	return nil
}

func wasmFixtureSecret(t *testing.T) string {
	t.Helper()
	var value [24]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func wasmPostgresTarget(t *testing.T, f *privateSeparatedFixture) (*pgx.ConnConfig, *pgx.Conn) {
	t.Helper()
	role, password := "portable_"+strings.ToLower(wasmFixtureSecret(t)[:12]), wasmFixtureSecret(t)
	created := false
	t.Cleanup(func() {
		if !created {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := f.inspect.ExecContext(ctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Error("drop portable application role", err)
		}
	})
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "portable-sdk")
	admin, err := pgx.Connect(t.Context(), databaseURL)
	if err != nil {
		t.Fatal("connect application database", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := admin.Close(ctx); err != nil {
			t.Error("close portable application observer", err)
		}
	})
	if _, err := admin.Exec(t.Context(), "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN PASSWORD '"+password+"'"); err != nil {
		t.Fatal("create scoped portable application role", err)
	}
	created = true
	if _, err := admin.Exec(t.Context(), "CREATE TABLE public.portable_writes(id text PRIMARY KEY, value integer NOT NULL); GRANT USAGE ON SCHEMA public TO "+pgx.Identifier{role}.Sanitize()+"; GRANT SELECT, INSERT ON public.portable_writes TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal("prepare portable transaction table", err)
	}
	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.User, config.Password = role, password
	return config, admin
}

func wasmMySQLTarget(t *testing.T) (string, wasmFixtureCredentials, *controlv1.ProjectTargetTLS) {
	t.Helper()
	value, err := url.Parse(*wasmMySQLURL)
	if err != nil || value.Scheme != "mysql" || value.User == nil || value.Hostname() == "" || value.Port() == "" || value.RawQuery != "" || value.Fragment != "" {
		t.Fatal("-tnl-wasm-mysql-url requires mysql://user:password@host:port/database from a disposable Task-owned MySQL")
	}
	password, _ := value.User.Password()
	credentials := wasmFixtureCredentials{User: value.User.Username(), Password: password, Database: strings.TrimPrefix(value.Path, "/")}
	if credentials.User == "" || credentials.Database == "" {
		t.Fatal("-tnl-wasm-mysql-url requires an application user and database")
	}
	config := mysql.NewConfig()
	config.User, config.Passwd, config.DBName, config.Net, config.Addr = credentials.User, credentials.Password, credentials.Database, "tcp", value.Host
	config.Timeout, config.ReadTimeout, config.WriteTimeout = 5*time.Second, 5*time.Second, 5*time.Second
	var trust *controlv1.ProjectTargetTLS
	if *wasmMySQLCA != "" || *wasmMySQLHostname != "" {
		if *wasmMySQLCA == "" || *wasmMySQLHostname == "" {
			t.Fatal("disposable MySQL target TLS requires both -tnl-wasm-mysql-ca-file and -tnl-wasm-mysql-tls-hostname")
		}
		pem, err := os.ReadFile(*wasmMySQLCA)
		if err != nil {
			t.Fatal("read disposable MySQL target CA", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			t.Fatal("disposable MySQL target CA contains no certificates")
		}
		name := "portable-" + wasmFixtureSecret(t)
		if err := mysql.RegisterTLSConfig(name, &tls.Config{RootCAs: roots, ServerName: *wasmMySQLHostname, MinVersion: tls.VersionTLS12}); err != nil {
			t.Fatal("register disposable MySQL verification", err)
		}
		t.Cleanup(func() { mysql.DeregisterTLSConfig(name) })
		config.TLSConfig = name
		value := serviceHTTPTestTargetTrust(*wasmMySQLHostname, string(pem))
		trust = &value
	}
	connector, err := mysql.NewConnector(config)
	if err != nil {
		t.Fatal("parse disposable MySQL target", err)
	}
	database := sql.OpenDB(connector)
	defer database.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		t.Fatal("disposable MySQL target readiness", err)
	}
	return value.Host, credentials, trust
}

func wasmFixtureAPI(t *testing.T, f *privateSeparatedFixture, token string, stopped chan struct{}, proxies map[string]*wasmCarrierProxy, observer *pgx.Conn, postgresServiceID string, issuer *githubtest.Issuer) *httptest.Server {
	t.Helper()
	var stopOnce sync.Once
	var observerMu sync.Mutex
	var isolationMu sync.Mutex
	isolationStages := make(map[string]chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /workload/assertion", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Execution string `json:"execution"`
		}
		if !decodeWASMFixtureRequest(w, r, &body) {
			return
		}
		execution, err := strconv.ParseUint(body.Execution, 10, 32)
		if err != nil || execution == 0 {
			http.Error(w, "invalid execution", http.StatusBadRequest)
			return
		}
		audience := f.controlConfig.ControlOrigin()
		now := time.Now()
		claims := githubtest.Claims(audience, now)
		claims["check_run_id"] = body.Execution
		claims["jti"] = body.Execution + "-" + strconv.FormatInt(now.UnixNano(), 10)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{"assertion": issuer.Sign(t, claims)})
	})
	mux.HandleFunc("POST /shutdown", func(w http.ResponseWriter, _ *http.Request) {
		stopOnce.Do(func() { close(stopped) })
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /fault/relay", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Address string `json:"address"`
			Blocked *bool  `json:"blocked"`
		}
		if !decodeWASMFixtureRequest(w, r, &body) {
			return
		}
		proxy := proxies[body.Address]
		if proxy == nil || body.Blocked == nil {
			http.Error(w, "requires a known address and blocked boolean", http.StatusBadRequest)
			return
		}
		closed := proxy.setBlocked(*body.Blocked)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"closed_connections": closed, "blocked": *body.Blocked, "boundary": "connector_wss_carrier"})
	})
	mux.HandleFunc("POST /postgres/carrier", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		var count int
		var address string
		if err := f.inspect.QueryRowContext(ctx, `SELECT count(*), COALESCE(min(slots->0->>'relay_address'),'')
			FROM control.connector_peer_pairs WHERE service_id=$1 AND retired_at IS NULL AND expires_at>now()`, postgresServiceID).Scan(&count, &address); err != nil {
			http.Error(w, "observe PostgreSQL connector carrier", http.StatusInternalServerError)
			return
		}
		if count != 1 || proxies[address] == nil {
			http.Error(w, "carrier proof requires one current PostgreSQL connector pair", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"address": address})
	})
	mux.HandleFunc("POST /observe/postgres", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID string `json:"id"`
		}
		if !decodeWASMFixtureRequest(w, r, &body) {
			return
		}
		if len(body.ID) < 1 || len(body.ID) > 128 {
			http.Error(w, "requires a bounded write ID", http.StatusBadRequest)
			return
		}
		observerMu.Lock()
		defer observerMu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		var count int
		if err := observer.QueryRow(ctx, "SELECT count(*) FROM public.portable_writes WHERE id=$1 AND value=42", body.ID).Scan(&count); err != nil {
			http.Error(w, "independent observer query failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"committed_rows": count})
	})
	// concurrent Worker requests rendezvous on observable events, not sleeps.
	// the first request closes its deployment before the second queries again.
	mux.HandleFunc("POST /isolation", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Run  string `json:"run"`
			Mark string `json:"mark"`
			Wait string `json:"wait"`
		}
		if !decodeWASMFixtureRequest(w, r, &body) {
			return
		}
		validStage := func(stage string) bool {
			return stage == "first-ready" || stage == "second-ready" || stage == "first-closed"
		}
		if len(body.Run) < 1 || len(body.Run) > 80 || !validStage(body.Mark) || !validStage(body.Wait) {
			http.Error(w, "invalid isolation rendezvous", http.StatusBadRequest)
			return
		}
		isolationMu.Lock()
		if len(isolationStages) >= 24 {
			isolationMu.Unlock()
			http.Error(w, "isolation rendezvous capacity reached", http.StatusTooManyRequests)
			return
		}
		stage := func(name string) chan struct{} {
			key := body.Run + "/" + name
			if isolationStages[key] == nil {
				isolationStages[key] = make(chan struct{})
			}
			return isolationStages[key]
		}
		marked, waited := stage(body.Mark), stage(body.Wait)
		select {
		case <-marked:
		default:
			close(marked)
		}
		isolationMu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		select {
		case <-waited:
			w.WriteHeader(http.StatusNoContent)
		case <-ctx.Done():
			http.Error(w, "concurrent request did not reach its isolation stage", http.StatusGatewayTimeout)
		}
	})
	// browser/workerd fixtures may redirect Fetch socket addressing here. this
	// forwards to the actual control handler and never issues an admission.
	control := &httputil.ReverseProxy{Transport: f.publicHTTP.Transport, Rewrite: func(proxy *httputil.ProxyRequest) {
		proxy.Out.URL.Scheme, proxy.Out.URL.Host = "https", strings.TrimPrefix(f.controlConfig.ControlOrigin(), "https://")
		proxy.Out.URL.Path = strings.TrimPrefix(proxy.In.URL.Path, "/control")
		proxy.Out.Host = proxy.Out.URL.Host
		proxy.Out.Header.Del("X-Tnl-Fixture-Token")
		proxy.Out.Header.Del("Origin")
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "fixture control forwarding failed", http.StatusBadGateway)
	}}
	mux.Handle("/control/", control)
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tnl-Fixture-Token")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Tnl-Fixture-Token")), []byte(token)) != 1 {
			http.Error(w, "fixture authentication required", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	api.Config.ReadTimeout, api.Config.WriteTimeout = 10*time.Second, 30*time.Second
	api.Start()
	t.Cleanup(func() { api.CloseClientConnections(); api.Close() })
	return api
}

func decodeWASMFixtureRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		http.Error(w, "invalid fixture request", http.StatusBadRequest)
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		http.Error(w, "fixture request requires one JSON value", http.StatusBadRequest)
		return false
	}
	return true
}

func TestWASMFixturePathRequiresPrivateNewFile(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "fixture.json")
	if err := validateWASMFixturePath(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateWASMFixturePath(path); err == nil {
		t.Fatal("existing file could be overwritten")
	}
	if err := validateWASMFixturePath("relative.json"); err == nil {
		t.Fatal("relative fixture path was accepted")
	}
	if err := validateWASMFixturePath(filepath.Join(directory, "missing", "fixture.json")); err == nil {
		t.Fatal("missing fixture parent was accepted")
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateWASMFixturePath(filepath.Join(directory, "other.json")); err == nil {
		t.Fatal("public fixture parent was accepted")
	}
}

func TestWASMFixtureRequestRejectsTrailingJSON(t *testing.T) {
	for _, body := range []string{`{"id":"one"} {"id":"two"}`, `{"unknown":true}`, `{"id":`} {
		t.Run(fmt.Sprintf("%q", body), func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			response := httptest.NewRecorder()
			var value struct {
				ID string `json:"id"`
			}
			if decodeWASMFixtureRequest(response, request, &value) || response.Code != http.StatusBadRequest {
				t.Fatal("invalid fixture request was accepted")
			}
		})
	}
}
