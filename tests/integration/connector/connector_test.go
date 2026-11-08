package connector_test

import (
	"bufio"
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
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/connectorfixture"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

// this runs the built connector owner and verifies TLS through two native relay
// carriers. no saved human state or external service participates.
func TestIntegrationConnectionConnectorOwnerHTTP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeOwner(t, "http", true)
}

func TestIntegrationConnectionConnectorOwnerKubernetes(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeOwner(t, "kubernetes", true)
}

func TestIntegrationConnectionConnectorOwnerSDKSelectionBudget(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	var baseline, selected map[string]int
	t.Run("baseline-sdk-sequence", func(t *testing.T) {
		baseline = runConnectionNativeOwnerStartup(t, "http", true, "baseline-sdk")
	})
	t.Run("native-sdk-selection", func(t *testing.T) {
		selected = runConnectionNativeOwnerStartup(t, "http", true, "native-sdk")
	})
	if !maps.Equal(baseline, selected) {
		t.Fatalf("native SDK selection changed the baseline SDK RPC budget: baseline=%v selected=%v", baseline, selected)
	}
	for _, language := range []string{"javascript", "python"} {
		t.Run(language, func(t *testing.T) {
			actual := runConnectionNativeOwnerStartup(t, "http", true, language)
			if !maps.Equal(baseline, actual) {
				t.Fatalf("%s SDK changed cold RPC budget: baseline=%v actual=%v", language, baseline, actual)
			}
		})
	}
}

func TestIntegrationConnectionConnectorOwnerSDKNativeWorkloadAcquisition(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	var baseline map[string]int
	for _, language := range []string{"javascript-provider", "python-provider"} {
		t.Run(language, func(t *testing.T) {
			actual := runConnectionNativeOwnerStartup(t, "http", true, language)
			total := 0
			for _, count := range actual {
				total += count
			}
			if total != 12 || baseline != nil && !maps.Equal(baseline, actual) {
				t.Fatalf("native provider changed the cold control budget: got %v, want twelve calls matching both SDKs", actual)
			}
			baseline = actual
		})
	}
}

func TestIntegrationConnectionConnectorOwnerSDKProcessContext(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeOwnerStartup(t, "http", true, "javascript-copies")
}

func TestIntegrationConnectionConnectorOwnerSDKPythonLifecycle(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeOwnerStartup(t, "http", true, "python-lifecycle")
}

func TestIntegrationConnectionConnectorOwnerSDKPythonPrepareTimeout(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	t.Run("registered", func(t *testing.T) {
		runConnectionNativeOwnerStartup(t, "http", true, "python-timeout")
	})
	t.Run("startup", func(t *testing.T) {
		runConnectionNativeOwnerStartup(t, "http", true, "python-startup-timeout")
	})
}

type connectorConnectionFixture struct {
	Handle   string
	Env      []string
	WrongTLS *atomic.Bool
	Canceled *atomic.Int32
	Stop     func()
}

func readSDKSelection(t *testing.T, directory, service string) (connectorruntime.SDKOwner, connectorruntime.Connection) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(directory, "tnl-sdk-*", "registry.json"))
	if err != nil || len(files) != 1 {
		t.Fatal("SDK did not create exactly one registry", files, err)
	}
	return readSDKRegistry(t, files[0], service)
}

func readSDKRegistry(t *testing.T, file, service string) (connectorruntime.SDKOwner, connectorruntime.Connection) {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		Owners map[string]struct {
			Owner connectorruntime.SDKOwner `json:"owner"`
		} `json:"owners"`
	}
	if err := json.Unmarshal(data, &registry); err != nil || len(registry.Owners) != 1 {
		t.Fatal("SDK did not select exactly one owner", err)
	}
	for _, record := range registry.Owners {
		handle, err := connectorruntime.ReadHandle(record.Owner.ConnectionHandle)
		if err != nil {
			t.Fatal(err)
		}
		var prepared connectorruntime.Prepared
		if err := connectorruntime.Call(t.Context(), record.Owner.ConnectionHandle, "prepared", connectorruntime.Request{Schema: 1, Directory: handle.Directory, ConfigDigest: handle.ConfigDigest, Service: service}, &prepared); err != nil {
			t.Fatal(err)
		}
		return record.Owner, prepared.Connection
	}
	t.Fatal("missing native SDK owner")
	return connectorruntime.SDKOwner{}, connectorruntime.Connection{}
}

func runConnectionNativeOwner(t *testing.T, protocol string, public bool, qualify ...func(connectorConnectionFixture)) {
	t.Helper()
	runConnectionNativeOwnerStartup(t, protocol, public, "caller-prepared", qualify...)
}

func runConnectionNativeOwnerStartup(t *testing.T, protocol string, public bool, startup string, qualify ...func(connectorConnectionFixture)) map[string]int {
	t.Helper()
	serviceName := "api"
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
	// retain the generated subject key identifier when signing strict TLS leaves.
	ca, err = x509.ParseCertificate(caDER)
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
	team, _ := opaqueid.New(opaqueid.TeamPrefix)
	service, _ := opaqueid.New(opaqueid.ServicePrefix)
	trustRevision := int64(1)
	sessionID, _ := opaqueid.New("wls_")
	serviceRun, _ := opaqueid.New(opaqueid.ServiceRunPrefix)
	allocated, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port = allocated.Addr().(*net.TCPAddr).Port
	_ = allocated.Close()
	native := connectorfixture.NewConnector(t, ca, caKey, service, serviceRun, sessionID, managedHostname, providerAddress)
	var revoked atomic.Bool
	renewed := make(chan struct{})
	var renewedOnce sync.Once
	var certificateRequests atomic.Int64
	type workloadSession struct {
		authorityv1.WorkloadSession
		public  ed25519.PublicKey
		revoked bool
	}
	sessions := map[string]*workloadSession{}
	var exchangeAttempts atomic.Int32
	var isolatedSDKContexts atomic.Bool
	var denySDKExchange, blockSDKExchange atomic.Bool
	var blockSDKPrepare atomic.Bool
	isolatedSDKContexts.Store(startup == "python-timeout" || startup == "python-startup-timeout")
	blockSDKPrepare.Store(startup == "python-timeout")
	blockSDKExchange.Store(startup == "python-startup-timeout")
	var deniedSDKExchanges atomic.Int32
	startupEntered, startupRelease := make(chan struct{}, 1), make(chan struct{})
	ownerKeys := map[string]*workloadSession{}
	var authorityMu sync.Mutex
	controlCalls := map[string]int{}
	issuer := githubtest.New(t)
	var verifier *oidc.GitHubWorkloadVerifier
	var providerAssertion, providerAudience string
	var peerAssertion string
	bindingFor := func(assertion string) string {
		if peerAssertion != "" && assertion == peerAssertion {
			return strings.Repeat("c", 64)
		}
		return strings.Repeat("b", 64)
	}
	var providerCalls atomic.Int32
	authority := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blockedExchange := r.URL.Path == "/v1/workload-sessions/exchange" && blockSDKExchange.Load()
		blockedPrepare := strings.HasSuffix(r.URL.Path, "/authorization") && blockSDKPrepare.Load()
		if blockedExchange || blockedPrepare {
			select {
			case startupEntered <- struct{}{}:
			default:
			}
			select {
			case <-startupRelease:
			case <-r.Context().Done():
				return
			}
		}
		authorityMu.Lock()
		defer authorityMu.Unlock()
		if r.URL.Path == "/sdk-provider-token" {
			bearer := "provider-cold"
			if providerCalls.Add(1) > 4 {
				bearer = "provider-warm"
			}
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+bearer || r.URL.Query().Get("audience") != providerAudience {
				t.Error("native provider acquisition used stale application inputs or wrong audience")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"value": providerAssertion})
			return
		}
		path := strings.ReplaceAll(strings.ReplaceAll(r.URL.Path, sessionID, "{session}"), service, "{service}")
		controlCalls[r.Method+" "+path]++
		current := sessions[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if current == nil {
			current = &workloadSession{}
		}
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
			_ = json.NewEncoder(w).Encode(authorityv1.WorkloadIdentity{Binding: bindingFor(input.Assertion), Services: []string{serviceName}, AssertionExpiresAt: time.Unix(claims.ExpiresAt, 0)})
		case r.URL.Path == "/v1/workload-sessions/"+current.Id+"/assertions":
			var input authorityv1.WorkloadAssertion
			if json.NewDecoder(r.Body).Decode(&input) != nil {
				w.WriteHeader(400)
				return
			}
			claims, err := verifier.Verify(r.Context(), input.Assertion)
			signature, decodeErr := base64.RawURLEncoding.DecodeString(input.Signature)
			if err != nil || decodeErr != nil || current.revoked || !ed25519.Verify(current.public, workloadproof.Attach(current.Id, claims.AssertionDigest), signature) {
				w.WriteHeader(403)
				return
			}
			current.AssertionExpiresAt = new(time.Unix(claims.ExpiresAt, 0))
			if current.AssertionExpiresAt.After(current.IdentityExpiresAt) {
				current.IdentityExpiresAt = *current.AssertionExpiresAt
			}
			_ = json.NewEncoder(w).Encode(current)
		case strings.HasSuffix(r.URL.Path, "/authorization"):
			if current.Id == "" || current.revoked {
				w.WriteHeader(403)
				return
			}
			_ = json.NewEncoder(w).Encode(controlv1.WorkloadServiceAuthorization{Subject: current.Subject, ServiceId: service, ValidUntil: current.LeaseExpiresAt, PolicyRevision: 1})
		case r.URL.Path == "/v1/workload-sessions/exchange":
			if denySDKExchange.Load() {
				deniedSDKExchanges.Add(1)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var exchange authorityv1.WorkloadExchange
			if json.NewDecoder(r.Body).Decode(&exchange) != nil {
				w.WriteHeader(400)
				return
			}
			claims, err := verifier.Verify(r.Context(), exchange.Assertion)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			public, err := base64.RawURLEncoding.DecodeString(exchange.PublicKey)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			current = ownerKeys[exchange.PublicKey]
			if current == nil {
				if len(ownerKeys) > 0 && !isolatedSDKContexts.Load() {
					t.Error("exchange retried with another owner key")
					w.WriteHeader(403)
					return
				}
				// isolation begins only after the original lost-reply retry and
				// warm budget checks. each new context must supply a fresh key.
				id := sessionID
				if len(ownerKeys) > 0 {
					id, err = opaqueid.New("wls_")
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					native.AllowWorkload(id)
				}
				credential := make([]byte, 32)
				if _, err := rand.Read(credential); err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				current = &workloadSession{public: ed25519.PublicKey(public), WorkloadSession: authorityv1.WorkloadSession{Id: id, TeamId: team, ProjectKey: exchange.ProjectKey, Workload: exchange.Workload, Provider: controlv1.WorkloadGitHub, Github: &authorityv1.WorkloadGitHubExecution{RepositoryId: "12345", RepositoryOwnerId: "6789", RunId: "111", RunAttempt: "1", CheckRunId: "222"}, Credential: "wlc_" + base64.RawURLEncoding.EncodeToString(credential), ExpiresAt: time.Now().Add(time.Hour), IdentityExpiresAt: time.Unix(claims.ExpiresAt, 0), LeaseExpiresAt: time.Now().Add(90 * time.Second), RenewAfter: time.Now().Add(30 * time.Second), ServiceIds: []string{service}, Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, Binding: bindingFor(exchange.Assertion)}}
				ownerKeys[exchange.PublicKey] = current
				sessions[current.Credential] = current
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
		case r.URL.Path == "/v1/workload-sessions/"+current.Id+"/renew":
			if current.revoked {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var renewal authorityv1.WorkloadRenewal
			if json.NewDecoder(r.Body).Decode(&renewal) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			signature, err := base64.RawURLEncoding.DecodeString(renewal.Signature)
			if err != nil || !ed25519.Verify(current.public, workloadproof.Renew(current.Id, renewal.Sequence), signature) || renewal.Sequence < 1 || renewal.Sequence < current.RenewalSequence || renewal.Sequence > current.RenewalSequence+1 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if renewal.Sequence != current.RenewalSequence {
				current.RenewalSequence = renewal.Sequence
				current.LeaseExpiresAt = time.Now().Add(90 * time.Second)
				current.RenewAfter = time.Now().Add(30 * time.Second)
			}
			_ = json.NewEncoder(w).Encode(current)
		case r.URL.Path == "/v1/workload/services":
			_ = json.NewEncoder(w).Encode(map[string]any{"services": []any{map[string]any{"id": service, "service": serviceName, "protocol": protocol, "endpoint": map[string]any{"hostname": managedHostname, "port": port, "public": public}}}})
		case strings.HasSuffix(r.URL.Path, "/run"):
			_ = json.NewEncoder(w).Encode(map[string]any{"service_id": service, "service_run_id": serviceRun, "run_number": 1, "protocol": protocol, "trust_revision": trustRevision, "expires_at": time.Now().Add(time.Minute), "subject": current.Subject, "endpoint": map[string]any{"hostname": managedHostname, "port": port, "public": public}, "pair_ready": native.Ready})
		case strings.Contains(r.URL.Path, "/connector-peer-pairs"):
			var requested controlv1.ConnectorPeerPairRequest
			var source controlv1.VisitorTokenWorkloadSource
			if json.NewDecoder(r.Body).Decode(&requested) != nil || json.Unmarshal(requested.Source, &source) != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			current = sessions[source.Credential]
			if current == nil || current.revoked || requested.Subject.WorkloadSessionId == nil || *requested.Subject.WorkloadSessionId != current.Id {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			pair, err := native.Prepare(r.Context(), requested, current.public)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if requested.Action == "renew" {
				_ = json.NewEncoder(w).Encode(controlv1.ConnectorPeerPairRenewal{Pair: pair, RunValidUntil: pair.ExpiresAt,
					Protocol: controlv1.ServiceProtocol(protocol), TrustRevision: trustRevision,
					Endpoint: controlv1.ServiceEndpoint{Hostname: managedHostname, Port: port, Public: public},
					VisitorPermission: controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: service},
						Hostname: managedHostname, Port: port, ServiceTrustRevision: &trustRevision, VisitorPolicyRevision: 1, VisitorToken: "fixture-connector-visitor-token", ExpiresAt: pair.ExpiresAt}})
				renewedOnce.Do(func() { close(renewed) })
				return
			}
			_ = json.NewEncoder(w).Encode(pair)
		case r.URL.Path == "/v1/visitor-tokens":
			var requested controlv1.VisitorTokenRequest
			var source controlv1.VisitorTokenWorkloadSource
			if json.NewDecoder(r.Body).Decode(&requested) != nil || json.Unmarshal(requested.Source, &source) != nil || requested.Resource.Kind != "service" || requested.Resource.Id != service {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			current = sessions[source.Credential]
			if current == nil || current.revoked {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(controlv1.VisitorTokenResponse{Resource: requested.Resource, Hostname: managedHostname, Port: port, ServiceTrustRevision: &trustRevision, VisitorPolicyRevision: 1, VisitorToken: "fixture-connector-visitor-token", ExpiresAt: time.Now().Add(time.Minute)})
		case strings.HasSuffix(r.URL.Path, "/client-certificate"):
			certificateRequests.Add(1)
			w.WriteHeader(403)
		case r.Method == "DELETE":
			if strings.HasPrefix(r.URL.Path, "/v1/workload-sessions/") {
				current.revoked = true
				revoked.Store(true)
			}
			w.WriteHeader(204)
		default:
			t.Error("unexpected connector owner fixture request", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	authority.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	authority.StartTLS()
	defer func() {
		select {
		case <-startupRelease:
		default:
			close(startupRelease)
		}
		authority.Close()
	}()
	server := strings.Replace(authority.URL, "127.0.0.1", "localhost", 1)
	verifier, err = oidc.NewGitHubWorkloadVerifier(server, issuer.Client)
	if err != nil {
		t.Fatal(err)
	}
	target := "http://unused.invalid:3000"
	targetDefinition := map[string]any{"type": "address", "address": target}
	if protocol == "kubernetes" {
		targetDefinition = map[string]any{"type": "eks", "cluster": "fixture", "region": "us-east-1"}
	}
	config := map[string]any{"version": 1, "tnl": map[string]any{"server": server, "team": team, "publisher_groups": map[string]any{"remote": map[string]any{"public": public}}, "services": map[string]any{serviceName: map[string]any{"publisher_group": "remote", "protocol": protocol, "target": targetDefinition}}, "workloads": map[string]any{"test": map[string]any{"github": map[string]any{"workflow": ".github/workflows/test.yml", "branch": "main", "events": []string{"push"}}, "services": []string{serviceName}}}}}
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
	build.Dir = "../../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("native build: %v %s", err, output)
	}
	// the SDK resolves its native package by platform and matching version.
	// supply this test's built binary without installing an unrelated ORM.
	manifest, err := os.ReadFile("../../../packages/ts/package.json")
	if err != nil {
		t.Fatal(err)
	}
	var sdk struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifest, &sdk); err != nil {
		t.Fatal(err)
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	packageName := fmt.Sprintf("tnl-%s-%s", runtime.GOOS, arch)
	packageDir := filepath.Join(root, "node_modules", "@tnldotdev", packageName)
	if err := os.MkdirAll(filepath.Join(packageDir, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(fmt.Sprintf(`{"name":"@tnldotdev/%s","version":%q}`, packageName, sdk.Version)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(binary, filepath.Join(packageDir, "bin", "tnl")); err != nil {
		t.Fatal(err)
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
	env = append(env, "SSL_CERT_FILE="+caPath, "NODE_EXTRA_CA_CERTS="+caPath, "NODE_PATH="+filepath.Join(root, "node_modules"))
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
	var scope connectorruntime.Context
	if err := json.Unmarshal(call(nil, "context", "--directory", root, "--workload", "test"), &scope); err != nil {
		t.Fatal(err)
	}
	assertion := issuer.Sign(t, githubtest.Claims(server, time.Now()))
	if startup == "python-timeout" || startup == "python-startup-timeout" {
		claims := githubtest.Claims(server, time.Now())
		claims["run_id"], claims["jti"] = "112", "peer-assertion"
		authorityMu.Lock()
		peerAssertion = issuer.Sign(t, claims)
		authorityMu.Unlock()
		if err := os.WriteFile(filepath.Join(root, "peer-assertion"), []byte(peerAssertion), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if strings.HasPrefix(startup, "javascript") || strings.HasPrefix(startup, "python") {
		manifest := workloadmanifest.Manifest{Schema: 1, Server: scope.Server, Team: scope.TeamID, ProjectKey: scope.ProjectKey, SourceFingerprint: scope.SourceID, ProjectLabel: scope.ProjectLabel,
			Workloads: map[string]workloadmanifest.Workload{"test": {Provider: "github", Services: []string{serviceName}, MaxDurationSeconds: 3600, Acquisition: workloadmanifest.Acquisition{Method: "github-actions", Audience: scope.Server}}}, Services: map[string]string{serviceName: protocol}}
		if err := manifest.Validate(); err != nil {
			t.Fatal(err)
		}
		generated := filepath.Join(root, ".tnl", "generated")
		if err := os.MkdirAll(generated, 0o700); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(manifest)
		if err := os.WriteFile(filepath.Join(generated, "workloads.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "assertion"), []byte(assertion), 0o600); err != nil {
			t.Fatal(err)
		}
		fixture, _ := filepath.Abs("../../../packages/ts/test/fixtures/connections/native-selection.ts")
		ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, "node", fixture)
		if startup == "javascript-copies" {
			child = exec.CommandContext(ctx, "node", fixture, "copies")
		}
		child.Env = append(slices.Clone(env), "TMPDIR="+root)
		if startup == "javascript-provider" {
			child.Args = append(child.Args, "provider")
		}
		if strings.HasPrefix(startup, "python") {
			python, _ := filepath.Abs("../../../packages/py/.venv/bin/python")
			fixture, _ := filepath.Abs("../../../packages/py/tests/native_selection.py")
			source, _ := filepath.Abs("../../../packages/py/src")
			child = exec.CommandContext(ctx, python, fixture, binary)
			child.Env = append(slices.Clone(env), "PYTHONPATH="+source, "TMPDIR="+root)
			if startup == "python-provider" {
				child.Args = append(child.Args, "provider")
			}
			if startup == "python-lifecycle" {
				child.Args = append(child.Args, "lifecycle")
			}
			if startup == "python-timeout" || startup == "python-startup-timeout" {
				fixture, _ := filepath.Abs("../../../packages/py/tests/native_prepare_timeout.py")
				child.Args = []string{python, fixture, binary}
				if startup == "python-startup-timeout" {
					child.Args = append(child.Args, "startup")
				}
			}
		}
		if strings.HasSuffix(startup, "-provider") {
			authorityMu.Lock()
			providerAssertion, providerAudience = assertion, scope.Server
			authorityMu.Unlock()
			child.Env = append(child.Env, "GITHUB_ACTIONS=true", "ACTIONS_ID_TOKEN_REQUEST_URL="+server+"/sdk-provider-token?audience=wrong", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=provider-cold")
		}
		child.Dir = root
		input, err := child.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := child.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var diagnostics bytes.Buffer
		child.Stderr = &diagnostics
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			input.Close()
			if err := child.Wait(); err != nil {
				t.Errorf("%s SDK: %v %s", startup, err, diagnostics.String())
			}
		}()
		lines := bufio.NewScanner(output)
		if startup == "python-timeout" || startup == "python-startup-timeout" {
			if !lines.Scan() || lines.Text() != "timed-out" {
				t.Fatal("Python did not time out after native owner registration")
			}
			select {
			case <-startupEntered:
			case <-ctx.Done():
				t.Fatal("native preparation did not reach its blocked boundary")
			}
			blockSDKPrepare.Store(false)
			blockSDKExchange.Store(false)
			close(startupRelease)
			_, _ = io.WriteString(input, "released\n")
			if !lines.Scan() || lines.Text() != "joined" {
				t.Fatal("Python close did not join the timed-out preparation while preserving its healthy peer")
			}
			authorityMu.Lock()
			calls := maps.Clone(controlCalls)
			authorityMu.Unlock()
			return calls
		}
		if !lines.Scan() || lines.Text() != "cold" {
			t.Fatal("SDK did not complete cold selection")
		}
		owner, first := readSDKSelection(t, root, serviceName)
		authorityMu.Lock()
		cold := maps.Clone(controlCalls)
		authorityMu.Unlock()
		_, _ = io.WriteString(input, "warm\n")
		if !lines.Scan() || lines.Text() != "warm" {
			t.Fatal("SDK did not complete warm selection")
		}
		nextOwner, next := readSDKSelection(t, root, serviceName)
		if owner != nextOwner || first.TransportID != next.TransportID || !first.ExpiresAt.Equal(next.ExpiresAt) || first.Port != next.Port {
			t.Fatal("warm SDK selection replaced the owner, transport, port, or fixed expiry")
		}
		authorityMu.Lock()
		warm := maps.Clone(controlCalls)
		authorityMu.Unlock()
		if !maps.Equal(cold, warm) {
			t.Fatalf("%s warm SDK preparation made control RPCs: cold=%v after=%v", startup, cold, warm)
		}
		if strings.HasSuffix(startup, "-provider") && providerCalls.Load() != 15 {
			t.Fatalf("native provider acquisition was coalesced or repeated: got %d, want four concurrent cold plus ten warm and one healthy retry", providerCalls.Load())
		}
		if startup == "javascript-copies" {
			isolatedSDKContexts.Store(true)
			_, _ = io.WriteString(input, "isolate\n")
			if !lines.Scan() || lines.Text() != "isolated" {
				t.Fatal("SDK did not preserve project, state, and server isolation")
			}
			registries, err := filepath.Glob(filepath.Join(root, "tnl-sdk-*", "registry.json"))
			if err != nil || len(registries) != 4 {
				t.Fatal("expected four isolated native registries", registries, err)
			}
			transports := map[string]bool{}
			ports := map[int]bool{}
			for _, registry := range registries {
				isolatedOwner, snapshot := readSDKRegistry(t, registry, serviceName)
				if transports[snapshot.TransportID] || ports[snapshot.Port] {
					t.Fatal("isolated contexts shared a transport or listener")
				}
				transports[snapshot.TransportID], ports[snapshot.Port] = true, true
				if isolatedOwner == owner && (snapshot.TransportID != first.TransportID || snapshot.Port != first.Port || !snapshot.ExpiresAt.Equal(first.ExpiresAt)) {
					t.Fatal("isolated context replaced the original transport or fixed expiry")
				}
			}
			authorityMu.Lock()
			keys := len(ownerKeys)
			authorityMu.Unlock()
			if keys != 4 || exchangeAttempts.Load() != 5 {
				t.Fatalf("isolated contexts reused owner keys or repeated exchange: keys=%d exchanges=%d", keys, exchangeAttempts.Load())
			}
		}
		if startup == "python-lifecycle" {
			isolatedSDKContexts.Store(true)
			phase := func(send, want string) {
				t.Helper()
				_, _ = io.WriteString(input, send+"\n")
				if !lines.Scan() || lines.Text() != want {
					t.Fatalf("Python lifecycle: expected %s, got %s", want, lines.Text())
				}
			}
			phase("lifecycle", "joined")
			blockSDKExchange.Store(true)
			phase("startup", "starting")
			select {
			case <-startupEntered:
			case <-ctx.Done():
				t.Fatal("startup did not reach native exchange")
			}
			phase("close", "closing")
			blockSDKExchange.Store(false)
			close(startupRelease)
			if !lines.Scan() || lines.Text() != "startup-joined" {
				t.Fatal("close did not join native startup")
			}
			denySDKExchange.Store(true)
			phase("failure", "denied")
			denySDKExchange.Store(false)
			phase("retained", "retained")
			if deniedSDKExchanges.Load() != 1 {
				t.Fatal("retained failure retried native authentication", deniedSDKExchanges.Load())
			}
			phase("retry", "recovered")
			t.Log("real Python lifecycle: borrowed close, concurrent joined close, stale alias, cleanup retry, close during startup, retained denial identity, and explicit retry passed")
		}
		_, _ = io.WriteString(input, "stop\n")
		t.Logf("%s SDK decoded cold and ten warm native responses with stable transport and expiry; cold=%v warm=0", startup, cold)
		return cold
	}
	request, _ := json.Marshal(connectorruntime.StartRequest{Schema: 1, Context: scope, Assertion: assertion})
	var state connectorruntime.Status
	startArgs := []string{"start", "--directory", root, "--workload", "test", "--runner-temp", root}
	if protocol == "kubernetes" {
		path := filepath.Join(root, "cluster-token")
		if err := os.WriteFile(path, []byte("fixture-cluster-token"), 0o600); err != nil {
			t.Fatal(err)
		}
		startArgs = append(startArgs, "--kube-token-file", path, "--namespace", "runtime-test")
	}
	if startup != "caller-prepared" {
		// reproduce d0825a78's SDK sequence against the same real native owner,
		// authority, signed assertion, relay carriers, and TLS preflight. this is
		// a baseline operation sequence, not a separately built historical SDK.
		privateRequest := connectorruntime.Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, Service: serviceName, Assertion: assertion}
		operation := "prepare"
		registry := ""
		defer func() {
			if registry != "" {
				call(nil, "sdk-stop", "--registry", registry, "--parent-pid", strconv.Itoa(os.Getpid()))
			} else if state.ConnectionHandle != "" {
				call(nil, "stop", "--handle", state.ConnectionHandle)
			}
		}()
		if startup == "baseline-sdk" {
			call(request, "identity", "--directory", root, "--workload", "test")
			startArgs = append(startArgs, "--parent-pid", strconv.Itoa(os.Getpid()))
			if err := json.Unmarshal(call(request, startArgs...), &state); err != nil {
				t.Fatal(err)
			}
			var prepared connectorruntime.Prepared
			if err := connectorruntime.Call(t.Context(), state.ConnectionHandle, operation, privateRequest, &prepared); err != nil {
				t.Fatal(err)
			}
			if err := connectorruntime.ValidatePrepared(prepared, serviceName); err != nil {
				t.Fatal(err)
			}
		} else {
			var err error
			registry, err = connectorruntime.NewDirectory(root)
			if err != nil {
				t.Fatal(err)
			}
			input, _ := json.Marshal(map[string]any{"schema": 1, "assertion": assertion})
			var prepared connectorruntime.SDKPrepared
			if err := json.Unmarshal(call(input, "sdk-prepare", "--directory", root, "--workload", "test", "--registry", registry, "--parent-pid", strconv.Itoa(os.Getpid()), "--selected-service", serviceName), &prepared); err != nil {
				t.Fatal(err)
			}
			state = connectorruntime.Status{ConnectionHandle: prepared.Owner.ConnectionHandle}
			if err := connectorruntime.ValidatePrepared(prepared.Prepared, serviceName); err != nil {
				t.Fatal(err)
			}
			operation, privateRequest.Workload = "sdk-prepare", "test"
		}
		authorityMu.Lock()
		cold := maps.Clone(controlCalls)
		authorityMu.Unlock()
		client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		defer client.CloseIdleConnections()
		for range 10 {
			var prepared connectorruntime.Prepared
			if operation == "sdk-prepare" {
				// use the same authenticated private HTTP operation as the SDK;
				// the caller-prepared Go Call adapter intentionally has no SDK verb.
				handle, err := connectorruntime.ReadHandle(state.ConnectionHandle)
				if err != nil {
					t.Fatal(err)
				}
				data, _ := json.Marshal(privateRequest)
				request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, handle.URL+"/v1/connections/sdk-prepare", bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Authorization", "Bearer "+handle.Key)
				request.Header.Set("Content-Type", "application/json")
				response, err := client.Do(request)
				if err != nil {
					t.Fatal("warm SDK IPC", err)
				}
				var selected connectorruntime.SDKPrepared
				err = connectorruntime.ReadJSON(response.Body, &selected)
				response.Body.Close()
				if response.StatusCode != http.StatusOK || err != nil {
					t.Fatal("warm SDK IPC returned an invalid snapshot", response.StatusCode, err)
				}
				if selected.Owner.ConnectionHandle != state.ConnectionHandle {
					t.Fatal("warm SDK selection replaced its owner")
				}
				prepared = selected.Prepared
			} else if err := connectorruntime.Call(t.Context(), state.ConnectionHandle, operation, privateRequest, &prepared); err != nil {
				t.Fatal(err)
			}
			if err := connectorruntime.ValidatePrepared(prepared, serviceName); err != nil {
				t.Fatal(err)
			}
		}
		authorityMu.Lock()
		warm := maps.Clone(controlCalls)
		authorityMu.Unlock()
		if !maps.Equal(cold, warm) {
			t.Fatalf("warm SDK preparation made control RPCs: cold=%v after=%v", cold, warm)
		}
		if cold["POST /v1/workload-sessions/identity"] != 2 || cold["POST /v1/workload-sessions/exchange"] != 2 {
			t.Fatal("SDK budget omitted selector identification or lost-exchange retry", cold)
		}
		total := 0
		for _, n := range cold {
			total += n
		}
		if total != 12 {
			t.Fatalf("SDK cold RPC budget=%d, want 12 including one lost-exchange retry: %v", total, cold)
		}
		t.Logf("%s control RPCs: cold=%d warm(10 requests)=0; includes two identity calls and one injected lost-exchange retry; by endpoint=%v", startup, total, cold)
		return cold
	}
	if err := json.Unmarshal(call(request, startArgs...), &state); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if state.ConnectionHandle != "" {
			call(nil, "stop", "--handle", state.ConnectionHandle)
		}
	}()
	if state.PID == os.Getpid() || state.State != "ready" {
		t.Fatal("no detached connector owner")
	}
	if data, err := os.ReadFile(state.ConnectionHandle); err != nil || bytes.Contains(data, []byte("traceparent")) || bytes.Contains(data, []byte("1111111111111111")) {
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
	var prepared connectorruntime.Prepared
	if err := connectorruntime.ReadJSON(bytes.NewReader(call(nil, "read", "--handle", state.ConnectionHandle, "--service", serviceName)), &prepared); err != nil {
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
			case "connector.connections.startup":
				startup = span
			case "client.connections.read":
				read = span
			case "connector.connections.read":
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
	if prepared.Schema != 1 || prepared.ProjectRuntime.Services[serviceName].Hostname != managedHostname || prepared.ProjectRuntime.Services[serviceName].Public != public {
		t.Fatal("prepared read did not preserve the owner's public metadata")
	}
	if snapshot.Schema != 1 || snapshot.Host != "127.0.0.1" || snapshot.Port != port || snapshot.SSL == nil || snapshot.SSL.ServerName != managedHostname || !snapshot.SSL.RejectUnauthorized {
		t.Fatal("prepared snapshot lost local dialing, managed TLS identity, or credential-free admission")
	}
	preparedJSON, _ := json.Marshal(snapshot)
	if bytes.Contains(preparedJSON, []byte(`"cert"`)) || bytes.Contains(preparedJSON, []byte(`"key"`)) {
		t.Fatal("prepared connection exported application client credentials")
	}
	// both built-owner cases must cross background renewal before exercising
	// their prepared connections; a fast startup must not hide a stale fixture.
	select {
	case <-renewed:
	case <-time.After(3 * time.Second):
		t.Fatal("built connector owner did not renew its retained pair")
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
		if err := json.Unmarshal(call(nil, "kube-credential", "--handle", state.ConnectionHandle, "--service", serviceName), &credential); err != nil {
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
	if protocol == "http" || protocol == "kubernetes" {
		fixture, err := filepath.Abs("../../../packages/ts/test/fixtures/connections/native-runtime.ts")
		if err != nil {
			t.Fatal(err)
		}
		node := exec.CommandContext(t.Context(), "node", fixture, protocol)
		node.Dir, node.Env = root, append(slices.Clone(env), "TNL_CONNECTION_HANDLE="+state.ConnectionHandle)
		if output, err := node.CombinedOutput(); err != nil {
			t.Fatalf("native SDK runtime: %v %s", err, output)
		}
	}
	if protocol == "http" && visits.Load() != 4 || protocol == "kubernetes" && visits.Load() != 1 {
		t.Fatal("SDK requests were not delivered exactly once")
	}
	for _, check := range qualify {
		check(connectorConnectionFixture{Handle: state.ConnectionHandle, Env: slices.Clone(env), WrongTLS: &wrongTLS, Canceled: &canceled, Stop: func() {
			call(nil, "stop", "--handle", state.ConnectionHandle)
		}})
	}
	call(nil, "stop", "--handle", state.ConnectionHandle)
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
		t.Fatal("connector owner requested application certificates")
	}
	// cleanup is already joined; avoid a second stop with an expired handle.
	state.ConnectionHandle = ""
	return nil
}
