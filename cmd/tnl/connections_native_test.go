package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
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
	"github.com/tnldotdev/tnl/internal/connectionruntime"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/targettransport"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	"github.com/tnldotdev/tnl/internal/workloadproof"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

// this runs the built native owner and verifies TLS through its admitted ingress
// streams. no saved human state or service outside these local fixtures participates.
func TestIntegrationConnectionNativeOwnerHTTP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeOwner(t, "", "http", true)
}

func TestIntegrationConnectionNativeOwnerKubernetes(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeOwner(t, "", "kubernetes", true)
}

func TestIntegrationConnectionDrizzleKit(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, public := range []bool{true, false} {
		t.Run(map[bool]string{true: "public", false: "private"}[public], func(t *testing.T) {
			runConnectionNativeOwner(t, testutil.NewDisposablePostgresDatabaseURL(t, "connection_drizzle"), "postgres", public)
		})
	}
}

type nativeConnectionFixture struct {
	Handle   string
	Env      []string
	WrongTLS *atomic.Bool
	Canceled *atomic.Int32
	Stop     func()
}

func runConnectionNativeOwner(t *testing.T, databaseURL, protocol string, public bool, qualify ...func(nativeConnectionFixture)) {
	t.Helper()
	serviceName := "api"
	if databaseURL != "" {
		serviceName = "database"
	}
	if protocol == "kubernetes" {
		serviceName = "cluster"
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	caPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{Subject: pkix.Name{CommonName: "connection fixture root"}, SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const managedHostname = "service.example.test"
	serverLeaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost", managedHostname}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverLeaf, ca, serverPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pair := tls.Certificate{Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverKey}
	wrongLeaf := *serverLeaf
	wrongLeaf.DNSNames = []string{"wrong.example.test"}
	wrongDER, err := x509.CreateCertificate(rand.Reader, &wrongLeaf, ca, serverPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongPair := tls.Certificate{Certificate: [][]byte{wrongDER, caDER}, PrivateKey: serverKey}
	var wrongTLS atomic.Bool
	var canceled atomic.Int32
	var visits atomic.Int32
	application := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Traceparent") != "" || r.Header.Get("Tracestate") != "" || r.Header.Get("Baggage") != "" {
			t.Error("native tracing injected application headers")
		}
		if len(r.TLS.PeerCertificates) != 0 {
			t.Error("connector requested an application client certificate")
			return
		}
		if r.URL.Path == "/hang" {
			_, _ = io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			canceled.Add(1)
			return
		}
		data, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || string(data) != "streamed-body" || r.Header.Get("Authorization") != "Bearer application-only" {
			t.Error("fetch changed the application request")
		}
		visits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(201)
		_, _ = w.Write(data)
	}))
	application.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.NoClientCert, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if wrongTLS.Load() {
			return &wrongPair, nil
		}
		return &pair, nil
	}}
	application.StartTLS()
	defer application.Close()
	_, portString, _ := net.SplitHostPort(application.Listener.Addr().String())
	port, _ := strconv.Atoi(portString)
	providerAddress := application.Listener.Addr().String()
	if databaseURL != "" {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		port = listener.Addr().(*net.TCPAddr).Port
		providerAddress = listener.Addr().String()
		backend, err := url.Parse(databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer connection.Close()
					_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
					var sslRequest [8]byte
					if _, err := io.ReadFull(connection, sslRequest[:]); err != nil {
						return
					}
					if sslRequest != targettransport.PostgresSSLRequest {
						return
					}
					if _, err := connection.Write([]byte{'S'}); err != nil {
						return
					}
					secured := tls.Server(connection, application.TLS)
					if err := secured.HandshakeContext(t.Context()); err != nil {
						return
					}
					provider, err := net.DialTimeout("tcp", backend.Host, 3*time.Second)
					if err != nil {
						return
					}
					defer provider.Close()
					_, _ = streamcopy.Copy(secured, provider)
				}()
			}
		}()
	}
	team, _ := opaqueid.New(opaqueid.TeamPrefix)
	service, _ := opaqueid.New(opaqueid.PrivateServicePrefix)
	sessionID, _ := opaqueid.New("wls_")
	privateRun, _ := opaqueid.New(opaqueid.PrivateRunPrefix)
	allocated, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port = allocated.Addr().(*net.TCPAddr).Port
	_ = allocated.Close()
	assignments, trusts := connectionIngressFixture(t, ca, caKey, caPEM, service, sessionID, providerAddress)
	var revoked atomic.Bool
	var certificateRequests atomic.Int64
	var current authorityv1.WorkloadSession
	var clientPublic ed25519.PublicKey
	var exchangeAttempts atomic.Int32
	var authorityMu sync.Mutex
	issuer := githubtest.New(t)
	var verifier *oidcauth.GitHubWorkloadVerifier
	authority := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorityMu.Lock()
		defer authorityMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/workload-sessions/identity":
			var input authorityv1.WorkloadIdentityRequest
			if json.NewDecoder(r.Body).Decode(&input) != nil {
				w.WriteHeader(400)
				return
			}
			claims, err := verifier.Verify(r.Context(), input.Assertion)
			if err != nil {
				w.WriteHeader(403)
				return
			}
			_ = json.NewEncoder(w).Encode(authorityv1.WorkloadIdentity{Binding: strings.Repeat("b", 64), Services: []string{serviceName}, AssertionExpiresAt: time.Unix(claims.ExpiresAt, 0)})
		case r.URL.Path == "/v1/workload-sessions/"+sessionID+"/assertions":
			var input authorityv1.WorkloadAssertion
			if json.NewDecoder(r.Body).Decode(&input) != nil {
				w.WriteHeader(400)
				return
			}
			claims, err := verifier.Verify(r.Context(), input.Assertion)
			signature, decodeErr := base64.RawURLEncoding.DecodeString(input.Signature)
			if err != nil || decodeErr != nil || r.Header.Get("Authorization") != "Bearer "+current.Credential || !ed25519.Verify(clientPublic, workloadproof.Attach(sessionID, claims.AssertionDigest), signature) {
				w.WriteHeader(403)
				return
			}
			current.AssertionExpiresAt = new(time.Unix(claims.ExpiresAt, 0))
			_ = json.NewEncoder(w).Encode(current)
		case strings.HasSuffix(r.URL.Path, "/authorization"):
			if revoked.Load() {
				w.WriteHeader(403)
				return
			}
			_ = json.NewEncoder(w).Encode(controlv1.WorkloadServiceAuthorization{Subject: current.Subject, ServiceId: service, ValidUntil: current.LeaseExpiresAt, PolicyRevision: 1})
		case r.URL.Path == "/v1/workload-sessions/exchange":
			var exchange authorityv1.WorkloadExchange
			if json.NewDecoder(r.Body).Decode(&exchange) != nil {
				w.WriteHeader(400)
				return
			}
			if _, err := verifier.Verify(r.Context(), exchange.Assertion); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			public, err := base64.RawURLEncoding.DecodeString(exchange.PublicKey)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			if current.Id == "" {
				clientPublic = ed25519.PublicKey(public)
				current = authorityv1.WorkloadSession{Id: sessionID, TeamId: team, ProjectKey: exchange.ProjectKey, Workload: exchange.Workload, Provider: controlv1.WorkloadGitHub, Github: &authorityv1.WorkloadGitHubExecution{RepositoryId: "12345", RepositoryOwnerId: "6789", RunId: "111", RunAttempt: "1", CheckRunId: "222"}, Credential: "wlc_" + strings.Repeat("x", 43), ExpiresAt: time.Now().Add(time.Hour), LeaseExpiresAt: time.Now().Add(90 * time.Second), RenewAfter: time.Now().Add(30 * time.Second), ServiceIds: []string{service}, Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &sessionID}}
				current.Binding = strings.Repeat("b", 64)
			} else if !ed25519.PublicKey(public).Equal(clientPublic) {
				t.Error("exchange retried with another owner key")
				w.WriteHeader(403)
				return
			}
			if exchangeAttempts.Add(1) == 1 {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = connection.Close()
				return
			}
			_ = json.NewEncoder(w).Encode(current)
		case r.URL.Path == "/v1/workload-sessions/"+sessionID+"/renew":
			if revoked.Load() || r.Header.Get("Authorization") != "Bearer "+current.Credential {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			current.LeaseExpiresAt = time.Now().Add(90 * time.Second)
			current.RenewAfter = time.Now().Add(30 * time.Second)
			_ = json.NewEncoder(w).Encode(current)
		case r.URL.Path == "/v1/workload/services":
			_ = json.NewEncoder(w).Encode(map[string]any{"services": []any{map[string]any{"id": service, "service": serviceName, "protocol": protocol, "managed_tls": map[string]any{"hostname": managedHostname, "port": port, "public": public}}}})
		case strings.HasSuffix(r.URL.Path, "/run"):
			_ = json.NewEncoder(w).Encode(map[string]any{"private_service_id": service, "private_run_id": privateRun, "run_number": 1, "protocol": protocol, "trust_revision": 1, "expires_at": time.Now().Add(time.Minute), "subject": current.Subject, "managed_tls": map[string]any{"hostname": managedHostname, "port": port, "public": public}})
		case strings.HasSuffix(r.URL.Path, "/ingress-assignments"):
			_ = json.NewEncoder(w).Encode(map[string]any{"subject": current.Subject, "assignments": assignments})
		case strings.HasSuffix(r.URL.Path, "/transport-trust"):
			parts := strings.Split(r.URL.Path, "/")
			_ = json.NewEncoder(w).Encode(trusts[parts[len(parts)-2]])
		case strings.HasSuffix(r.URL.Path, "/client-certificate"):
			certificateRequests.Add(1)
			w.WriteHeader(403)
		case r.Method == "DELETE":
			if strings.HasPrefix(r.URL.Path, "/v1/workload-sessions/") {
				revoked.Store(true)
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	authority.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	authority.StartTLS()
	defer authority.Close()
	server := strings.Replace(authority.URL, "127.0.0.1", "localhost", 1)
	verifier, err = oidcauth.NewGitHubWorkloadVerifier(server, issuer.Client)
	if err != nil {
		t.Fatal(err)
	}
	target := "http://unused.invalid:3000"
	if protocol == "postgres" {
		target = "unused.invalid:5432"
	}
	targetDefinition := map[string]any{"type": "address", "address": target}
	if protocol == "kubernetes" {
		targetDefinition = map[string]any{"type": "eks", "cluster": "fixture", "region": "us-east-1"}
	}
	config := map[string]any{"version": 1, "tnl": map[string]any{"server": server, "team": team, "publishers": map[string]any{"remote": map[string]any{"public": public}}, "services": map[string]any{serviceName: map[string]any{"publisher": "remote", "protocol": protocol, "target": targetDefinition}}, "workloads": map[string]any{"test": map[string]any{"provider": "github", "github": map[string]any{"workflow": ".github/workflows/test.yml", "ref": "refs/heads/main", "events": []string{"push"}}, "services": []string{serviceName}}}}}
	data, _ := json.Marshal(config)
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://github.com/fixture/shop.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v %s", err, output)
		}
	}
	binary := filepath.Join(root, "tnl")
	build := exec.CommandContext(t.Context(), "go", "build", "-race", "-o", binary, "./cmd/tnl")
	build.Dir = "../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("native build: %v %s", err, output)
	}
	caPath := filepath.Join(root, "root.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "TNL_") && !strings.HasPrefix(value, "OTEL_") {
			env = append(env, value)
		}
	}
	env = append(env, "SSL_CERT_FILE="+caPath, "NODE_EXTRA_CA_CERTS="+caPath)
	var traceMu sync.Mutex
	var spans []*tracepb.Span
	collector := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		var batch collectortrace.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &batch); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if bytes.Contains(body, []byte("application-only")) || bytes.Contains(body, []byte("streamed-body")) || bytes.Contains(body, []byte("PRIVATE KEY")) {
			t.Error("trace exported private application data")
		}
		traceMu.Lock()
		for _, resource := range batch.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				spans = append(spans, scope.Spans...)
			}
		}
		traceMu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	collector.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	collector.StartTLS()
	defer collector.Close()
	env = append(env, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="+strings.Replace(collector.URL, "127.0.0.1", "localhost", 1)+"/v1/traces", "OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE="+caPath, "OTEL_METRICS_EXPORTER=none", "OTEL_LOGS_EXPORTER=none", "OTEL_BSP_SCHEDULE_DELAY=10", "OTEL_EXPORTER_OTLP_TIMEOUT=1000")
	call := func(input []byte, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, append([]string{"--no-telemetry", "runtime", "connections"}, args...)...)
		parent := "00-11111111111111111111111111111111-2222222222222222-00"
		if args[0] == "read" {
			parent = "00-33333333333333333333333333333333-4444444444444444-01"
		}
		command.Env = append(slices.Clone(env), "TNL_TRACEPARENT="+parent)
		command.Stdin = bytes.NewReader(input)
		var output, diagnostics bytes.Buffer
		command.Stdout = &output
		command.Stderr = &diagnostics
		if err := command.Run(); err != nil {
			t.Fatalf("native call: %v %s", err, diagnostics.Bytes())
		}
		return output.Bytes()
	}
	var scope connectionruntime.Context
	if err := json.Unmarshal(call(nil, "context", "--directory", root, "--workload", "test"), &scope); err != nil {
		t.Fatal(err)
	}
	assertion := issuer.Sign(t, githubtest.Claims(server, time.Now()))
	request, _ := json.Marshal(connectionruntime.StartRequest{Schema: 1, Context: scope, Assertion: assertion})
	var state connectionruntime.Status
	startArgs := []string{"start", "--directory", root, "--workload", "test", "--runner-temp", root}
	if protocol == "kubernetes" {
		path := filepath.Join(root, "cluster-token")
		if err := os.WriteFile(path, []byte("fixture-cluster-token"), 0o600); err != nil {
			t.Fatal(err)
		}
		startArgs = append(startArgs, "--kube-token-file", path, "--namespace", "runtime-test")
	}
	if err := json.Unmarshal(call(request, startArgs...), &state); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if state.PrivateHandle != "" {
			call(nil, "stop", "--handle", state.PrivateHandle)
		}
	}()
	if state.PID == os.Getpid() || state.State != "ready" {
		t.Fatal("no detached native owner")
	}
	if data, err := os.ReadFile(state.PrivateHandle); err != nil || bytes.Contains(data, []byte("traceparent")) || bytes.Contains(data, []byte("1111111111111111")) {
		t.Fatal("launch parent persisted in handle")
	}
	if probe, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		_ = probe.Close()
		t.Fatal("caller-prepared CLI readiness left its selected service listener unbound")
	}
	encoded, _ := json.Marshal(state)
	if bytes.Contains(encoded, []byte("BEGIN")) || bytes.Contains(encoded, []byte(assertion)) {
		t.Fatal("startup disclosed credentials")
	}
	// a prepared read must use the existing owner even after configuration and
	// Git disappear; only startup may evaluate these inputs or authenticate.
	if err := os.Remove(filepath.Join(root, "tnl.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, ".git")); err != nil {
		t.Fatal(err)
	}
	var prepared connectionruntime.Prepared
	if err := connectionruntime.ReadJSON(bytes.NewReader(call(nil, "read", "--handle", state.PrivateHandle, "--service", serviceName)), &prepared); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		traceMu.Lock()
		var launch, startup, read, ipc, connector *tracepb.Span
		for _, span := range spans {
			switch span.Name {
			case "client.connections.launch":
				launch = span
			case "native.connections.startup":
				startup = span
			case "client.connections.read":
				read = span
			case "native.connections.read":
				if bytes.Equal(span.TraceId, bytes.Repeat([]byte{0x33}, 16)) {
					ipc = span
				}
			case "connector.startup":
				connector = span
			}
		}
		complete := launch != nil && startup != nil && read != nil && ipc != nil && connector != nil
		if complete {
			if len(connector.ParentSpanId) != 0 || len(connector.Links) != 1 || !bytes.Equal(connector.Links[0].SpanId, startup.SpanId) {
				t.Error("backend lost the process owner or retained startup parentage")
			}
			if !bytes.Equal(launch.ParentSpanId, bytes.Repeat([]byte{0x22}, 8)) || !bytes.Equal(startup.ParentSpanId, launch.SpanId) || !bytes.Equal(startup.TraceId, launch.TraceId) || !bytes.Equal(read.ParentSpanId, bytes.Repeat([]byte{0x44}, 8)) || !bytes.Equal(ipc.ParentSpanId, read.SpanId) || bytes.Equal(ipc.TraceId, startup.TraceId) {
				t.Error("CLI launch/detached owner/per-IPC parent chain differs")
			}
		}
		traceMu.Unlock()
		if complete {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("CLI launch/detached owner/per-IPC spans missing")
		}
		time.Sleep(10 * time.Millisecond)
	}
	snapshot := prepared.Connection
	if prepared.Schema != 1 || prepared.PublicRuntime.Services[serviceName].Hostname != managedHostname || prepared.PublicRuntime.Services[serviceName].Public != public {
		t.Fatal("prepared read did not preserve the owner's public metadata")
	}
	if snapshot.Schema != 1 || snapshot.Host != "127.0.0.1" || snapshot.Port != port || snapshot.SSL == nil || snapshot.SSL.ServerName != managedHostname || !snapshot.SSL.RejectUnauthorized {
		t.Fatal("prepared snapshot lost local dialing, managed TLS identity, or credential-free admission")
	}
	preparedJSON, _ := json.Marshal(snapshot)
	if bytes.Contains(preparedJSON, []byte(`"cert"`)) || bytes.Contains(preparedJSON, []byte(`"key"`)) {
		t.Fatal("prepared connection exported application client credentials")
	}
	if protocol == "http" {
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: snapshot.SSL.ServerName}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(snapshot.Host, strconv.Itoa(snapshot.Port)))
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport}
		for range 2 {
			request, _ := http.NewRequestWithContext(t.Context(), "POST", snapshot.URL+"/echo", strings.NewReader("streamed-body"))
			request.Header.Set("Authorization", "Bearer application-only")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != 201 || string(body) != "streamed-body" {
				t.Fatal("HTTP stream changed")
			}
		}
	}
	if protocol == "kubernetes" {
		var credential credentialv1.ExecCredential
		if err := json.Unmarshal(call(nil, "kube-credential", "--handle", state.PrivateHandle, "--service", serviceName), &credential); err != nil {
			t.Fatal(err)
		}
		if credential.APIVersion != "client.authentication.k8s.io/v1" || credential.Status == nil || credential.Status.Token != "fixture-cluster-token" || credential.Status.ClientCertificateData != "" || credential.Status.ClientKeyData != "" || credential.Status.ExpirationTimestamp == nil {
			t.Fatal("native Kubernetes helper did not compose its credentials")
		}
		data, err := os.ReadFile(state.Kubeconfig)
		if err != nil || bytes.Contains(data, []byte("PRIVATE KEY")) || bytes.Contains(data, []byte("fixture-cluster-token")) {
			t.Fatal("session kubeconfig persisted credential material")
		}
		if !bytes.Contains(data, []byte("https://127.0.0.1:"+strconv.Itoa(port))) || !bytes.Contains(data, []byte("tls-server-name: "+managedHostname)) {
			t.Fatal("kubeconfig lost separate dial host and TLS identity", string(data))
		}
	}
	if databaseURL != "" {
		backend, err := url.Parse(databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		password, _ := backend.User.Password()
		if err := os.MkdirAll(filepath.Join(root, "migrations/meta"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "migrations/meta/_journal.json"), []byte(`{"version":"7","dialect":"postgresql","entries":[{"idx":0,"version":"7","when":1700000000000,"tag":"0000_sdk","breakpoints":true}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "migrations/0000_sdk.sql"), []byte("CREATE TABLE sdk_migration (id integer PRIMARY KEY);"), 0o600); err != nil {
			t.Fatal(err)
		}
		fixture, err := filepath.Abs("../../packages/ts/fixtures/connections/installed-drizzle.ts")
		if err != nil {
			t.Fatal(err)
		}
		node := exec.CommandContext(t.Context(), "node", fixture, binary)
		node.Dir, node.Env = root, append(slices.Clone(env), "TNL_CONNECTION_HANDLE="+state.PrivateHandle, "DB_USER="+backend.User.Username(), "DB_PASSWORD="+password, "DB_NAME="+strings.TrimPrefix(backend.Path, "/"))
		if output, err := node.CombinedOutput(); err != nil {
			t.Fatalf("installed Drizzle Kit: %v %s", err, output)
		}
	}
	if protocol == "http" || protocol == "kubernetes" {
		fixture, err := filepath.Abs("../../packages/ts/fixtures/connections/installed-drizzle.ts")
		if err != nil {
			t.Fatal(err)
		}
		node := exec.CommandContext(t.Context(), "node", fixture, binary, protocol)
		node.Dir, node.Env = root, append(slices.Clone(env), "TNL_CONNECTION_HANDLE="+state.PrivateHandle)
		if output, err := node.CombinedOutput(); err != nil {
			t.Fatalf("native SDK runtime: %v %s", err, output)
		}
	}
	if protocol == "http" && visits.Load() != 4 || protocol == "kubernetes" && visits.Load() != 1 {
		t.Fatal("SDK requests were not delivered exactly once")
	}
	if databaseURL != "" {
		database, err := pgx.Connect(t.Context(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close(context.Background())
		var table string
		if err := database.QueryRow(t.Context(), "SELECT to_regclass('public.sdk_migration')::text").Scan(&table); err != nil || table != "sdk_migration" {
			t.Fatalf("Drizzle Kit did not apply migration: %v", err)
		}
	}
	for _, check := range qualify {
		check(nativeConnectionFixture{Handle: state.PrivateHandle, Env: slices.Clone(env), WrongTLS: &wrongTLS, Canceled: &canceled, Stop: func() {
			call(nil, "stop", "--handle", state.PrivateHandle)
		}})
	}
	call(nil, "stop", "--handle", state.PrivateHandle)
	if state.Kubeconfig != "" {
		if _, err := os.Stat(state.Kubeconfig); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("session kubeconfig survived owner cleanup")
		}
	}
	if !revoked.Load() {
		t.Fatal("owner stop did not revoke workload")
	}
	if exchangeAttempts.Load() != 2 {
		t.Fatal("lost exchange response was not recovered by the same owner")
	}
	if certificateRequests.Load() != 0 {
		t.Fatal("native owner requested application certificates")
	}
	// cleanup is already joined; avoid a second stop with an expired handle.
	state.PrivateHandle = ""
}
