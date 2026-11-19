package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var (
	publisherWASMFile     = flag.String("tnl-publisher-wasm-fixture-file", "", "private actual Go/WASM publisher fixture descriptor")
	publisherWASMCommand  = flag.String("tnl-publisher-wasm-fixture-command", "", "actual Go/WASM publisher runner JSON argv; {fixture} expands to the private descriptor")
	publisherWASMDuration = flag.Duration("tnl-publisher-wasm-fixture-duration", 6*time.Minute, "maximum actual Go/WASM publisher fixture lifetime")
)

type publisherWASMDescriptor struct {
	Version             int                `json:"version"`
	Project             string             `json:"project"`
	Deployment          string             `json:"deployment"`
	Token               string             `json:"token"`
	SiblingToken        string             `json:"sibling_token"`
	Enrollment          string             `json:"enrollment"`
	ControlURL          string             `json:"control_url"`
	ControlDialAddress  string             `json:"control_dial_address"`
	ControlRootPEM      string             `json:"control_root_pem"`
	RelayRootPEM        string             `json:"relay_root_pem"`
	ServiceRootPEM      string             `json:"service_root_pem"`
	NamedURL            string             `json:"named_url"`
	RestrictedURL       string             `json:"restricted_url"`
	Relays              []wasmFixtureRelay `json:"relays"`
	SPKIPins            []string           `json:"spki_pins"`
	APIURL              string             `json:"api_url"`
	APIToken            string             `json:"api_token"`
	RunnerCertificate   string             `json:"runner_certificate_pem"`
	RunnerPrivateKeyPEM string             `json:"runner_private_key_pem"`
}

type publisherWASMObservation struct {
	ServiceID         string `json:"service_id"`
	ServiceRunID      string `json:"service_run_id"`
	RunNumber         int64  `json:"run_number"`
	ActiveRuns        int    `json:"active_runs"`
	Deleted           bool   `json:"deleted"`
	Orders            int    `json:"orders"`
	Status            int    `json:"status"`
	Body              string `json:"body"`
	CertificateSHA256 string `json:"certificate_sha256"`
	PublisherRuntime  string `json:"publisher_runtime"`
}

// reuse PR1's separated control/relay topology, browser-addressable relay
// helpers and real ACME fixture. unlike portable owner unit tests, the external
// runner instantiates the packaged Go/WASM artifact; no publisher is injected.
func TestIntegrationPublisherWASMFixture(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *publisherWASMCommand == "" && *publisherWASMFile == "" {
		t.Skip("requires -tnl-publisher-wasm-fixture-command or -tnl-publisher-wasm-fixture-file")
	}
	if *publisherWASMDuration < time.Second || *publisherWASMDuration > 20*time.Minute {
		t.Fatal("-tnl-publisher-wasm-fixture-duration must be between 1s and 20m")
	}
	var argv []string
	if *publisherWASMCommand != "" {
		if err := json.Unmarshal([]byte(*publisherWASMCommand), &argv); err != nil || len(argv) == 0 || argv[0] == "" {
			t.Fatal("-tnl-publisher-wasm-fixture-command requires a nonempty JSON argument array")
		}
	}
	file := *publisherWASMFile
	if file == "" {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		file = filepath.Join(directory, "publisher.json")
	}
	if err := validateWASMFixturePath(file); err != nil {
		t.Fatal(err)
	}
	f := newServiceRuntimeFixture(t, false, nil)
	_, relays, pins := wasmFixtureRelays(t, f)
	ingress := startSeparatedPrivateIngress(t, f, 0, "wss", nil)
	mode, restricted, protocol := controlv1.Anonymous, controlv1.Restricted, controlv1.ServiceProtocolHTTP
	const project, deployment = "portable-publisher", "portable"
	applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), project, controlv1.ApplyProjectConfigurationRequest{
		TeamId: f.identity.teamID, Source: &testProjectSource, Deployment: deployment,
		ServiceDeclarations: controlv1.ProjectServiceDeclarations{"web": protocol, "restricted": protocol, "exact": protocol},
		Configuration: controlv1.ProjectConfiguration{
			Settings: &controlv1.DeploymentSettings{},
			Services: map[string]controlv1.ProjectServiceConfiguration{
				"web":        {Target: "app", Protocol: &protocol, Public: new(true), Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: &mode}}},
				"exact":      {Target: "app", Protocol: &protocol, Public: new(true), Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: &mode}}},
				"restricted": {Target: "app", Protocol: &protocol, Public: new(true), Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: &restricted}}},
			},
		},
	})
	if err != nil || applied.Deployments == nil || len(*applied.Deployments) != 1 {
		t.Fatal("apply portable publisher fixture", err)
	}
	configuration := applied.Configuration
	for name, binding := range configuration.Services {
		if name == "exact" {
			binding.PublisherAliasParent = new((*applied.Deployments)[0].Namespace)
			configuration.Services[name] = binding
		}
	}
	applied, err = f.identity.routes.ApplyProjectConfiguration(t.Context(), project, controlv1.ApplyProjectConfigurationRequest{
		TeamId: f.identity.teamID, Deployment: deployment, ExpectedRevision: applied.Revision,
		ServiceDeclarations: applied.ServiceDeclarations, Configuration: configuration,
	})
	if err != nil {
		t.Fatal("approve exact-run publisher fixture addresses", err)
	}
	request := controlv1.RegisterDeploymentCredentialRequest{
		ExpiresIn: 1200, DeploymentIds: new([]string{(*applied.Deployments)[0].Id}),
	}
	request.Permissions.Publish = &controlv1.DeploymentPublishSelection{
		Services:  new(controlv1.DeploymentCredentialServiceSelection{"web", "restricted", "exact"}),
		Temporary: new(controlv1.TemporaryPublicationAnonymous),
	}
	selection := controlv1.DeploymentCredentialServiceSelection{"web"}
	request.Permissions.Connect = &selection
	team, err := f.identity.authority.GetTeam(t.Context(), f.identity.teamID)
	if err != nil || team.DisplayName == "" {
		t.Fatal("read portable publisher team", err)
	}
	register := func(name string) string {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		input := request
		input.Name, input.PublicKey = name, base64.RawURLEncoding.EncodeToString(public)
		approval, err := f.identity.routes.RegisterDeploymentCredential(t.Context(), f.identity.teamID, project, name, input)
		if err != nil {
			t.Fatal("register portable publisher credential", err)
		}
		token, err := (auth.DeploymentCredential{
			Version: 1, ControlURL: f.controlConfig.ControlOrigin(), Team: team.DisplayName,
			Approval: approval, PrivateKey: base64.RawURLEncoding.EncodeToString(private),
		}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	token, siblingToken := register("portable-publisher"), register("alias-sibling")
	enrollment, err := f.identity.routes.CreateDeploymentPublisherEnrollment(
		t.Context(), f.identity.teamID, project, deployment, "managed-worker-fixture",
		controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: []string{"web"}, MaxMembers: new(1), ExpiresIn: new(600)},
	)
	if err != nil {
		t.Fatal("create disposable publisher enrollment", err)
	}
	addresses := make(map[string]string)
	for _, service := range applied.Services {
		if service.ServiceId == nil {
			t.Fatal("publisher fixture omitted its saved service")
		}
		saved, err := f.identity.routes.GetService(t.Context(), *service.ServiceId)
		if err != nil || saved.Endpoint == nil {
			t.Fatal("publisher fixture omitted its public endpoint", err)
		}
		addresses[service.Service] = "https://" + saved.Endpoint.Hostname
	}
	apiToken := wasmFixtureSecret(t)
	dial := workloadPublicEndpointDialer(t, ingress.ingresses[0].server, 443)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: f.visitorRoots.Clone(), DialContext: dial}
	t.Cleanup(transport.CloseIdleConnections)
	visitor := &http.Client{
		Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	stopped := make(chan struct{})
	api := newPublisherWASMAPI(t, f, apiToken, visitor, stopped, ingress.ingresses[0].server.RoutingObservedAt)
	leaf := api.TLS.Certificates[0]
	privateDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	pins = append(pins, base64.StdEncoding.EncodeToString(pin[:]))
	descriptor := publisherWASMDescriptor{
		Version: 1, Project: team.DisplayName + "/" + project, Deployment: deployment, Token: token, SiblingToken: siblingToken,
		Enrollment: enrollment.EnrollmentKey,
		ControlURL: f.controlConfig.ControlOrigin(), ControlDialAddress: f.publicControlAddress,
		ControlRootPEM: string(f.certificateAuthority.certificatePEM), RelayRootPEM: string(f.certificateAuthority.certificatePEM),
		ServiceRootPEM: string(f.visitorRootPEM), NamedURL: addresses["web"], RestrictedURL: addresses["restricted"],
		Relays: relays, SPKIPins: pins, APIURL: strings.Replace(api.URL, "127.0.0.1", "localhost", 1), APIToken: apiToken,
		RunnerCertificate:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})),
		RunnerPrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
	}
	data, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("create private publisher fixture", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error("remove private publisher fixture", err)
		}
	})
	_, writeErr := output.Write(data)
	if err := errors.Join(writeErr, output.Close()); err != nil {
		t.Fatal("write private publisher fixture", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), *publisherWASMDuration)
	defer cancel()
	if len(argv) == 0 {
		t.Log("actual Go/WASM publisher fixture ready; credentials remain in the private descriptor")
		select {
		case <-stopped:
		case <-ctx.Done():
			t.Fatal("publisher fixture ended without explicit shutdown", ctx.Err())
		}
		return
	}
	for index := range argv {
		argv[index] = strings.ReplaceAll(argv[index], "{fixture}", file)
	}
	command := exec.Command(argv[0], argv[1:]...)
	command.Dir = integrationRepositoryRoot(t)
	command.Stdout, command.Stderr, command.Stdin = os.Stdout, os.Stderr, os.Stdin
	finish := isolateIntegrationCommand(t, command)
	owner, err := startOwnedCommand(command, finish)
	if err != nil {
		t.Fatal("start actual Go/WASM publisher runner", err)
	}
	t.Cleanup(func() {
		if err := owner.shutdown(5*time.Second, 5*time.Second); err != nil {
			t.Error("actual Go/WASM publisher runner cleanup", err)
		}
	})
	select {
	case <-owner.done:
		if err := owner.result(); err != nil {
			t.Fatal("actual Go/WASM publisher runner", err)
		}
	case <-ctx.Done():
		t.Fatal("actual Go/WASM publisher runner exceeded fixture lifetime", ctx.Err())
	}
}

func newPublisherWASMAPI(t *testing.T, f *privateSeparatedFixture, token string, visitor *http.Client, stopped chan struct{}, routingObserved func() time.Time) *httptest.Server {
	t.Helper()
	var stopOnce sync.Once
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Tnl-Fixture-Token")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Tnl-Fixture-Token")), []byte(token)) != 1 {
			http.Error(w, "fixture authentication required", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/shutdown" {
			stopOnce.Do(func() { close(stopped) })
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/observe" && r.URL.Path != "/exercise" && r.URL.Path != "/unavailable" && r.URL.Path != "/state" && r.URL.Path != "/await-restartable" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			URL string `json:"url"`
		}
		if !decodeWASMFixtureRequest(w, r, &body) {
			return
		}
		address, err := url.Parse(body.URL)
		if err != nil || address.Scheme != "https" || address.User != nil || address.Port() != "" ||
			address.RawQuery != "" || address.Fragment != "" || address.Path != "" ||
			!strings.HasSuffix(address.Hostname(), "."+f.controlConfig.ManagedDomain) {
			http.Error(w, "requires an exact fixture service HTTPS origin", http.StatusBadRequest)
			return
		}
		timeout := 40 * time.Second
		if r.URL.Path == "/await-restartable" {
			timeout = 150 * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		var result publisherWASMObservation
		var readyAt time.Time
		err = f.inspect.QueryRowContext(ctx, `
			SELECT service.id,COALESCE(endpoint.service_run_id,''),service.deleted_at IS NOT NULL,
				COALESCE((SELECT max(run_number) FROM control.service_runs WHERE service_id=service.id
				    AND (endpoint.service_run_id IS NULL OR id=endpoint.service_run_id)),0),
				(SELECT count(*) FROM control.service_runs WHERE service_id=service.id AND closed_at IS NULL),
				(SELECT count(*) FROM control.acme_orders WHERE service_id=service.id),
				(SELECT COALESCE(max(ready_at),'epoch'::timestamptz) FROM control.service_runs WHERE service_id=service.id AND closed_at IS NULL)
			FROM control.services service
			JOIN control.service_endpoints endpoint ON endpoint.service_id=service.id
			WHERE endpoint.hostname=$1 AND service.team_id=$2
		`, address.Hostname(), f.identity.teamID).Scan(&result.ServiceID, &result.ServiceRunID, &result.Deleted, &result.RunNumber, &result.ActiveRuns, &result.Orders, &readyAt)
		if err != nil {
			http.Error(w, "observe saved fixture service", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/await-restartable" {
			// the runner has killed workerd. observe the original authority
			// deadline; never shorten a live run lease or forge a replacement.
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for {
				var current bool
				err := f.inspect.QueryRowContext(ctx, `SELECT EXISTS(
					SELECT 1 FROM control.service_runs
					WHERE service_id=$1 AND closed_at IS NULL AND publisher_expires_at>now()
				)`, result.ServiceID).Scan(&current)
				if err != nil {
					http.Error(w, "observe stopped runtime authority", http.StatusInternalServerError)
					return
				}
				if !current {
					break
				}
				select {
				case <-ctx.Done():
					http.Error(w, "stopped runtime authority did not expire", http.StatusGatewayTimeout)
					return
				case <-ticker.C:
				}
			}
		}
		if r.URL.Path == "/observe" || r.URL.Path == "/exercise" || r.URL.Path == "/unavailable" {
			if r.URL.Path == "/unavailable" {
				readyAt = time.Now()
			}
			// publication readiness and ingress's background observation are
			// separate events. wait on that actual observation, not a sleep.
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			for routingObserved().Before(readyAt) {
				select {
				case <-ctx.Done():
					http.Error(w, "ingress did not observe ready publication", http.StatusGatewayTimeout)
					return
				case <-ticker.C:
				}
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, body.URL+"/probe", nil)
			if err != nil {
				http.Error(w, "build fixture visitor", http.StatusInternalServerError)
				return
			}
			response, err := visitor.Do(request)
			if err != nil {
				if r.URL.Path == "/unavailable" {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(result)
					return
				}
				http.Error(w, "verified public visitor failed", http.StatusBadGateway)
				return
			}
			content, readErr := io.ReadAll(io.LimitReader(response.Body, 8193))
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || len(content) > 8192 ||
				response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || len(response.TLS.PeerCertificates) == 0 {
				http.Error(w, "verified public visitor response failed", http.StatusBadGateway)
				return
			}
			fingerprint := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
			result.Status, result.Body = response.StatusCode, string(content)
			result.CertificateSHA256 = hex.EncodeToString(fingerprint[:])
			result.PublisherRuntime = response.Header.Get("X-Publisher-Runtime")
			if r.URL.Path == "/exercise" {
				if err := exercisePublisherWASMPublicStream(ctx, visitor, body.URL); err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}))
	api.TLS = serviceRuntimeTLS(t, f.certificateAuthority, "localhost")
	api.Config.ReadTimeout, api.Config.WriteTimeout = 10*time.Second, 160*time.Second
	api.StartTLS()
	t.Cleanup(func() { api.CloseClientConnections(); api.Close() })
	return api
}

func exercisePublisherWASMPublicStream(ctx context.Context, visitor *http.Client, origin string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/stream", nil)
	if err != nil {
		return errors.New("build public stream request")
	}
	stream, err := visitor.Do(request)
	if err != nil {
		return errors.New("open public stream")
	}
	defer stream.Body.Close()
	first := make([]byte, len("first\n"))
	if _, err := io.ReadFull(stream.Body, first); err != nil || string(first) != "first\n" {
		return errors.New("public first chunk was not streamed")
	}
	release, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/release", nil)
	if err != nil {
		return errors.New("build public release request")
	}
	released, err := visitor.Do(release)
	if err != nil {
		return errors.New("release public stream from another request")
	}
	_, _ = io.Copy(io.Discard, released.Body)
	_ = released.Body.Close()
	tail, err := io.ReadAll(io.LimitReader(stream.Body, 32))
	if err != nil || string(tail) != "last\n" {
		return errors.New("public streamed response tail changed")
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cancelRequest, err := http.NewRequestWithContext(cancelCtx, http.MethodGet, origin+"/cancel", nil)
	if err != nil {
		return errors.New("build public cancel request")
	}
	held, err := visitor.Do(cancelRequest)
	if err != nil {
		return errors.New("open public cancel stream")
	}
	defer held.Body.Close()
	first = make([]byte, len("cancel-ready\n"))
	if _, err := io.ReadFull(held.Body, first); err != nil || string(first) != "cancel-ready\n" {
		return errors.New("public cancel stream did not reach handler")
	}
	cancel()
	_ = held.Body.Close()
	observation, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		request, err := http.NewRequestWithContext(observation, http.MethodGet, origin+"/evidence", nil)
		if err != nil {
			return errors.New("build public cancellation observation")
		}
		response, err := visitor.Do(request)
		if err != nil {
			return errors.New("observe public cancellation")
		}
		var evidence struct {
			Canceled       bool `json:"canceled"`
			RequestAborted bool `json:"requestAborted"`
		}
		err = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&evidence)
		_ = response.Body.Close()
		if err != nil {
			return errors.New("decode public cancellation observation")
		}
		if evidence.Canceled && evidence.RequestAborted {
			return nil
		}
		select {
		case <-observation.Done():
			return errors.New("public cancellation did not reach the Go/WASM handler")
		case <-ticker.C:
		}
	}
}
