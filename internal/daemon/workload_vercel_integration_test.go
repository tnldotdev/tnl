package tnldruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	authorityclient "github.com/tnldotdev/tnl/internal/client/authority"
	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	"github.com/tnldotdev/tnl/internal/config"
	tnldconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var vercelArtifacts = flag.String("tnl-vercel-artifacts", "", "directory for local Vercel function artifacts and nonsecret evidence")
var vercelLinuxNodeImage = flag.String("tnl-vercel-linux-node-image", "", "optional local digest-pinned Node 24.20.0 Linux x64 image; requires Docker host networking")

// the artifact owns its native visitor process. only local infrastructure TLS
// and issuer key discovery are redirected; authority and data paths are real.
func TestIntegrationWorkloadVercelFunction(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *vercelArtifacts == "" {
		t.Skip("requires the explicit artifact directory and pinned Node 24 setup from task go:test:integration:vercel")
	}
	issuer := githubtest.NewProvider(t, "https://oidc.vercel.com/acme")
	opened := make(chan privateObservation, 256)
	f := newPrivateRuntimeFixtureTiming(t, false, opened, false, func(_ *tnldconfig.Config, tr *http.Transport, _ *testCertificateAuthority) {
		base := tr.Clone()
		t.Cleanup(base.CloseIdleConnections)
		tr.RegisterProtocol("https", splitACMERoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "oidc.vercel.com" {
				return issuer.Client.Transport.RoundTrip(r)
			}
			return base.RoundTrip(r)
		}))
	})
	for slot := range 2 {
		startSeparatedPrivateIngress(t, f, slot, "tls-tcp", opened)
	}
	var targets atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targets.Add(1)
		if r.URL.Path != "/answer" || r.Header.Get("Authorization") != "Bearer application-only" || r.Header.Get("X-Vercel-Oidc-Token") != "" {
			t.Error("HTTP target lost application auth or received workload credentials")
			w.WriteHeader(400)
			return
		}
		_, _ = io.WriteString(w, "artifact HTTP target")
	}))
	t.Cleanup(target.Close)
	pg, err := pgx.ParseConfig(testutil.NewDisposablePostgresDatabaseURL(t, "vercel_target"))
	if err != nil {
		t.Fatal(err)
	}
	group, httpProtocol, pgProtocol := "private", controlv1.PrivateHttp, controlv1.Postgres
	pgTarget := countedVercelPostgresTarget(t, net.JoinHostPort(pg.Host, strconv.Itoa(int(pg.Port))), &targets)
	policies := map[string]controlv1.ProjectWorkload{"function": {
		Provider: controlv1.WorkloadVercel,
		Trust:    controlv1.WorkloadTrust{Provider: controlv1.WorkloadVercel, Issuer: "https://oidc.vercel.com/acme", JwksUrl: "https://oidc.vercel.com/acme/.well-known/jwks", Audience: "https://vercel.com/acme", Claims: map[string]string{"owner": "acme", "owner_id": "team_one", "project_id": "prj_store", "environment": "production"}},
		Services: []string{"api", "database"}, MaxDurationSeconds: 180,
	}}
	applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{
		TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64),
		Configuration: controlv1.ProjectConfiguration{Workloads: &policies, Publishers: map[string]controlv1.ProjectPublisherGroup{group: {}}, Services: map[string]controlv1.ProjectServiceConfiguration{
			"api":      {Publisher: &group, Protocol: &httpProtocol, Target: target.URL},
			"database": {Publisher: &group, Protocol: &pgProtocol, Target: pgTarget},
		}, Webhooks: map[string]controlv1.ProjectWebhook{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	startWorkloadPublishers(t, f, group, "tls-tcp")
	services := map[string]string{}
	for _, s := range applied.Services {
		if s.ServiceId != nil {
			services[*s.ServiceId] = s.Service
		}
	}
	var mu sync.Mutex
	calls := map[string]int{}
	prepared := map[string]bool{}
	sessions := map[string]authorityv1.WorkloadSession{}
	origin, _ := url.Parse(f.controlConfig.ControlOrigin())
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(origin) }}
	proxy.Transport = splitACMERoundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		calls[r.Method+" "+r.URL.Path]++
		for id, name := range services {
			if strings.Contains(r.URL.Path, "/"+id+"/") {
				prepared[name] = true
			}
		}
		mu.Unlock()
		return f.publicHTTP.Transport.RoundTrip(r)
	})
	proxy.ModifyResponse = func(r *http.Response) error {
		if r.Request.URL.Path != "/v1/workload-sessions/exchange" || r.StatusCode != 200 {
			return nil
		}
		body, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			return err
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var s authorityv1.WorkloadSession
		if err := json.Unmarshal(body, &s); err != nil {
			return err
		}
		mu.Lock()
		sessions[s.Id] = s
		mu.Unlock()
		return nil
	}
	front := httptest.NewUnstartedServer(proxy)
	front.TLS = privateRuntimeTLS(t, f.certificateAuthority, "localhost")
	front.StartTLS()
	t.Cleanup(front.Close)
	server := strings.Replace(front.URL, "127.0.0.1", "localhost", 1)

	output := *vercelArtifacts
	if output == "" {
		output = t.TempDir()
	}
	output, err = filepath.Abs(output)
	if err != nil {
		t.Fatal(err)
	}
	tool, err := filepath.Abs("../../tools/vercel-function-check")
	if err != nil {
		t.Fatal(err)
	}
	buildDir := t.TempDir()
	manifest, err := workloadmanifest.Generate(config.TNL{Server: &server, Team: &f.identity.teamID, Services: config.Services{
		"api": {Protocol: new("http")}, "database": {Protocol: new("postgres")},
	}, Workloads: map[string]config.Workload{"function": {Provider: "vercel", Services: []string{"api", "database"}, MaxDuration: new(config.Duration(180 * time.Second))}}}, projectconfig.SourceIdentity{Key: "workload", Fingerprint: strings.Repeat("a", 64), Label: "artifact"})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(buildDir, "workloads.json")
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	host, linux := filepath.Join(buildDir, "tnl-host"), filepath.Join(buildDir, "tnl-linux-x64")
	for _, b := range []struct{ path, goos, arch string }{{host, "", ""}, {linux, "linux", "amd64"}} {
		command := exec.CommandContext(t.Context(), "go", "build", "-o", b.path, "./cmd/tnl")
		command.Dir = "../.."
		command.Env = os.Environ()
		if b.goos != "" {
			command.Env = append(command.Env, "GOOS="+b.goos, "GOARCH="+b.arch, "CGO_ENABLED=0")
		}
		if result, err := command.CombinedOutput(); err != nil {
			t.Fatalf("native build: %v\n%s", err, result)
		}
	}
	command := exec.CommandContext(t.Context(), "node", filepath.Join(tool, "build.ts"), output, host, linux, manifestPath)
	if result, err := command.CombinedOutput(); err != nil {
		t.Fatalf("artifact build: %v\n%s", err, result)
	}
	trust := filepath.Join(buildDir, "roots.pem")
	if err := os.WriteFile(trust, append(slices.Clone(f.certificateAuthority.certificatePEM), f.visitorRootPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/stats":
			var names []string
			for name := range prepared {
				names = append(names, name)
			}
			slices.Sort(names)
			_ = json.NewEncoder(w).Encode(map[string]any{"sessions": len(sessions), "prepared": names, "targets": targets.Load(), "calls": calls})
		case "/revoke":
			client, err := authorityclient.New(f.controlConfig.ControlOrigin(), f.publicHTTP, "")
			if err == nil {
				for _, session := range sessions {
					if err = client.RevokeWorkloadSession(r.Context(), session.Id, session.Credential); err != nil {
						break
					}
				}
			}
			if err != nil {
				t.Error("real authority revocation failed", err)
				w.WriteHeader(500)
				return
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(controller.Close)
	now := time.Now()
	claims := map[string]any{"iss": "https://oidc.vercel.com/acme", "aud": "https://vercel.com/acme", "sub": "owner:acme:project:storefront:environment:production", "owner": "acme", "owner_id": "team_one", "project": "storefront", "project_id": "prj_store", "environment": "production", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	tokens := map[string]string{"valid": issuer.Sign(t, claims)}
	claims["exp"] = now.Add(6 * time.Minute).Unix()
	tokens["rotated"] = issuer.Sign(t, claims)
	claims["iat"], claims["nbf"], claims["exp"] = now.Add(-time.Hour).Unix(), now.Add(-time.Hour).Unix(), now.Add(-time.Minute).Unix()
	tokens["expired"] = issuer.Sign(t, claims)
	claims["iat"], claims["nbf"], claims["exp"], claims["project_id"] = now.Unix(), now.Unix(), now.Add(5*time.Minute).Unix(), "prj_wrong"
	tokens["wrong"] = issuer.Sign(t, claims)
	input, _ := json.Marshal(tokens)
	variants := []string{"host"}
	if *vercelLinuxNodeImage != "" {
		if !strings.Contains(*vercelLinuxNodeImage, "@sha256:") && !strings.HasPrefix(*vercelLinuxNodeImage, "sha256:") {
			t.Fatal("Linux Node image must be pinned by digest")
		}
		variants = append(variants, "linux-x64")
	}
	for _, variant := range variants {
		mu.Lock()
		calls, prepared, sessions = map[string]int{}, map[string]bool{}, map[string]authorityv1.WorkloadSession{}
		mu.Unlock()
		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
		command = exec.CommandContext(ctx, "node", filepath.Join(tool, "invoke.ts"), output, controller.URL, variant, *vercelLinuxNodeImage)
		command.Stdin = bytes.NewReader(input)
		command.Env = append(os.Environ(), "SSL_CERT_FILE="+trust, "NODE_EXTRA_CA_CERTS="+trust, "DB_USER="+pg.User, "DB_PASSWORD="+pg.Password, "DB_NAME="+pg.Database)
		result, err := command.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("%s artifact invocation: %v\n%s", variant, err, result)
		}
		t.Log(strings.TrimSpace(string(result)))
	}
	seen := map[string]bool{}
	for len(opened) > 0 {
		o := <-opened
		if o.header.Connector == nil || o.header.Connector.Subject.Kind != tunnelv1.VisitorWorkloadSession {
			t.Fatal("artifact bytes bypassed workload connector admission")
		}
		seen[services[o.header.PrivateServiceID]] = true
	}
	if !seen["api"] || !seen["database"] {
		t.Fatal("missing real ingress/relay/publisher evidence", seen)
	}
	var humans int
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.visitor_devices`).Scan(&humans); err != nil || humans != 0 {
		t.Fatal("artifact enrolled a human visitor", err)
	}
	t.Logf("artifact evidence: %s; real workload forwarding: %v", output, seen)
}

// count the actual publisher-to-PostgreSQL leg as well as HTTP target requests.
// the function receives database auth only, never this address or a direct URL.
func countedVercelPostgresTarget(t *testing.T, address string, targets *atomic.Int32) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer client.Close()
				backend, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
				if err != nil {
					return
				}
				defer backend.Close()
				stop := context.AfterFunc(ctx, func() { _ = client.Close(); _ = backend.Close() })
				defer stop()
				reader := bufio.NewReader(client)
				header, err := reader.Peek(8)
				if err != nil {
					return
				}
				// publisher health probes open sockets without application startup.
				if binary.BigEndian.Uint32(header[4:]) == 196608 {
					targets.Add(1)
				}
				joined := make(chan struct{})
				go func() { _, _ = io.Copy(backend, reader); _ = backend.(*net.TCPConn).CloseWrite(); close(joined) }()
				_, _ = io.Copy(client, backend)
				_ = client.Close()
				<-joined
			})
		}
	})
	t.Cleanup(func() { cancel(); _ = listener.Close(); workers.Wait() })
	return listener.Addr().String()
}
