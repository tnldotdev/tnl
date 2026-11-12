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
	"flag"
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	connectorworkload "github.com/tnldotdev/tnl/internal/connector/workload"
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

var connectionCLIBinary = flag.String("tnl-cli-binary", "", "CLI built by the connections Task before child lifecycle deadlines")

// this runs the built connector owner and verifies TLS through two native relay
// carriers. no saved human state or external service participates.
func TestIntegrationConnectionConnectorOwnerHTTP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeOwnerStartup(t, "http", "caller-prepared")
}

func TestIntegrationConnectionConnectorOwnerKubernetes(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeOwnerStartup(t, "kubernetes", "caller-prepared")
}

func TestIntegrationConnectionConnectorOwnerSDKSelectionBudget(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	var baseline, selected map[string]int
	t.Run("baseline-sdk-sequence", func(t *testing.T) {
		baseline = runConnectionNativeOwnerStartup(t, "http", "baseline-sdk")
	})
	t.Run("native-sdk-selection", func(t *testing.T) {
		selected = runConnectionNativeOwnerStartup(t, "http", "native-sdk")
	})
	if !maps.Equal(baseline, selected) {
		t.Fatalf("native SDK selection changed the baseline SDK RPC budget: baseline=%v selected=%v", baseline, selected)
	}
	for _, language := range []string{"javascript", "python"} {
		t.Run(language, func(t *testing.T) {
			actual := runConnectionNativeOwnerStartup(t, "http", language)
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
			actual := runConnectionNativeOwnerStartup(t, "http", language)
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

func TestIntegrationConnectionConnectorOwnerGoogleConfigAcquisition(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, source := range []string{"caller-assertion", "token-file", "token-env"} {
		t.Run(source, func(t *testing.T) {
			runConnectionNativeOwnerStartup(t, "http", "config-google-"+source)
		})
	}
}

func TestIntegrationConnectionConnectorOwnerSDKProcessContext(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeOwnerStartup(t, "http", "javascript-copies")
}

func TestIntegrationConnectionConnectorOwnerSDKPythonLifecycle(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runConnectionNativeOwnerStartup(t, "http", "python-lifecycle")
}

func TestIntegrationConnectionConnectorOwnerSDKPythonPrepareTimeout(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	t.Run("registered", func(t *testing.T) {
		runConnectionNativeOwnerStartup(t, "http", "python-timeout")
	})
	t.Run("startup", func(t *testing.T) {
		runConnectionNativeOwnerStartup(t, "http", "python-startup-timeout")
	})
}

func TestIntegrationConnectionConnectorOwnerSDKBackgroundRefresh(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, language := range []string{"javascript-refresh", "python-refresh", "borrowed-refresh"} {
		t.Run(language, func(t *testing.T) {
			t.Parallel()
			runConnectionNativeOwnerStartup(t, "http", language)
		})
	}
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

func runConnectionNativeOwnerStartup(t *testing.T, protocol, startup string) map[string]int {
	t.Helper()
	binary := *connectionCLIBinary
	if binary == "" {
		t.Fatal("run task go:test:integration:connections to build the connector CLI")
	}
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
	var visits atomic.Int32
	refreshAfter := make(chan struct{})
	var refreshStreams atomic.Int32
	application := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Traceparent") != "" || r.Header.Get("Tracestate") != "" || r.Header.Get("Baggage") != "" {
			t.Error("native tracing injected application headers")
		}
		if len(r.TLS.PeerCertificates) != 0 {
			t.Error("connector requested an application client certificate")
			return
		}
		if r.URL.Path == "/refresh-stream" {
			refreshStreams.Add(1)
			_, _ = io.WriteString(w, "before-proof\n")
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-refreshAfter:
			}
			_, _ = io.WriteString(w, "after-proof\n")
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
	application.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.NoClientCert, Certificates: []tls.Certificate{pair}}
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
	defer allocated.Close()
	var releasePort sync.Once
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
	googleConfig := strings.HasPrefix(startup, "config-google-")
	var issuer *githubtest.Issuer
	if googleConfig {
		issuer = githubtest.NewKeySet(t, config.GoogleWorkloadJWKS)
	} else {
		issuer = githubtest.New(t)
	}
	var verifyAssertion func(context.Context, string) (oidc.WorkloadExecution, error)
	var providerAssertion, providerAudience string
	var peerAssertion string
	bindingFor := func(assertion string) string {
		if peerAssertion != "" && assertion == peerAssertion {
			return strings.Repeat("c", 64)
		}
		return strings.Repeat("b", 64)
	}
	var providerCalls atomic.Int32
	var redirectedProviderCalls atomic.Int32
	providerCanceled := make(chan struct{}, 1)
	var proofMu sync.Mutex
	var actionProofs []string
	privateActionProofs := func() []string {
		proofMu.Lock()
		defer proofMu.Unlock()
		return slices.Clone(actionProofs)
	}
	refreshedProof := make(chan struct{}, 1)
	borrowedCrossing := make(chan struct{}, 1)
	borrowedRelease := make(chan struct{})
	var borrowedReleaseOnce sync.Once
	defer borrowedReleaseOnce.Do(func() { close(borrowedRelease) })
	var blockBorrowed atomic.Bool
	authority := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/authorization") && blockBorrowed.Load() {
			select {
			case borrowedCrossing <- struct{}{}:
			default:
			}
			select {
			case <-borrowedRelease:
			case <-r.Context().Done():
				return
			}
		}
		// this is the job runtime API, not the public GitHub token endpoint. it
		// shares only the fixture's TLS listener, never authority credentials.
		if r.URL.Path == "/action-provider-token" {
			sequence := providerCalls.Add(1)
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer action-private-runtime-bearer" || r.URL.Query().Get("audience") != providerAudience || r.URL.Query().Get("keep") != "yes" {
				t.Error("Action refresh used the wrong runtime source or selected audience")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			switch startup {
			case "action-unavailable":
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			case "action-redirect":
				w.Header().Set("Location", "/action-provider-redirected")
				w.WriteHeader(http.StatusFound)
				return
			case "action-stalled":
				w.WriteHeader(http.StatusOK)
				tick := time.NewTicker(10 * time.Millisecond)
				defer tick.Stop()
				defer func() {
					select {
					case providerCanceled <- struct{}{}:
					default:
					}
				}()
				for {
					select {
					case <-r.Context().Done():
						return
					case <-tick.C:
						_, _ = io.WriteString(w, " ")
						w.(http.Flusher).Flush()
					}
				}
			}
			claims := githubtest.Claims(providerAudience, time.Now())
			claims["jti"] = fmt.Sprintf("action-background-proof-%d", sequence)
			if startup == "action-replacement-job" {
				claims["check_run_id"] = "333"
			}
			w.Header().Set("Content-Type", "application/json")
			proof := issuer.Sign(t, claims)
			proofMu.Lock()
			actionProofs = append(actionProofs, proof)
			proofMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"value": proof})
			return
		}
		if r.URL.Path == "/action-provider-redirected" {
			redirectedProviderCalls.Add(1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
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
			claims, err := verifyAssertion(r.Context(), input.Assertion)
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
			claims, err := verifyAssertion(r.Context(), input.Assertion)
			signature, decodeErr := base64.RawURLEncoding.DecodeString(input.Signature)
			if err != nil || decodeErr != nil || current.revoked || !ed25519.Verify(current.public, workloadproof.Attach(current.Id, claims.AssertionDigest), signature) {
				w.WriteHeader(403)
				return
			}
			// attachment may extend proof time, never replace the original job.
			g := claims.GitHub
			if current.Provider == controlv1.WorkloadGitHub && (current.Github == nil || g == nil || g.RepositoryID != current.Github.RepositoryId || g.RepositoryOwnerID != current.Github.RepositoryOwnerId || g.RunID != current.Github.RunId || g.RunAttempt != current.Github.RunAttempt || g.CheckRunID != current.Github.CheckRunId) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			current.AssertionExpiresAt = new(time.Unix(claims.ExpiresAt, 0))
			if current.AssertionExpiresAt.After(current.IdentityExpiresAt) {
				current.IdentityExpiresAt = *current.AssertionExpiresAt
				current.LeaseExpiresAt = minTimeForFixture(current.RenewAfter.Add(time.Minute), connectorworkload.SessionDeadline(current.WorkloadSession))
				select {
				case refreshedProof <- struct{}{}:
				default:
				}
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
			claims, err := verifyAssertion(r.Context(), exchange.Assertion)
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
				var github *authorityv1.WorkloadGitHubExecution
				if g := claims.GitHub; g != nil {
					github = &authorityv1.WorkloadGitHubExecution{RepositoryId: g.RepositoryID, RepositoryOwnerId: g.RepositoryOwnerID, RunId: g.RunID, RunAttempt: g.RunAttempt, CheckRunId: g.CheckRunID}
				}
				current = &workloadSession{public: ed25519.PublicKey(public), WorkloadSession: authorityv1.WorkloadSession{Id: id, TeamId: team, ProjectKey: exchange.ProjectKey, Workload: exchange.Workload, Provider: controlv1.WorkloadGitHub, Github: github, Credential: "wlc_" + base64.RawURLEncoding.EncodeToString(credential), ExpiresAt: new(time.Now().Add(time.Hour)), IdentityExpiresAt: time.Unix(claims.ExpiresAt, 0), LeaseExpiresAt: time.Now().Add(90 * time.Second), RenewAfter: time.Now().Add(30 * time.Second), ServiceIds: []string{service}, Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, Binding: bindingFor(exchange.Assertion)}}
				if googleConfig {
					current.Provider, current.Github = controlv1.WorkloadGoogle, nil
				}
				ownerKeys[exchange.PublicKey] = current
				if strings.HasSuffix(startup, "-refresh") {
					current.ExpiresAt = nil
				}
				current.LeaseExpiresAt = minTimeForFixture(current.LeaseExpiresAt, connectorworkload.SessionDeadline(current.WorkloadSession))
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
				current.LeaseExpiresAt = minTimeForFixture(time.Now().Add(90*time.Second), connectorworkload.SessionDeadline(current.WorkloadSession))
				current.RenewAfter = time.Now().Add(30 * time.Second)
			}
			_ = json.NewEncoder(w).Encode(current)
		case r.URL.Path == "/v1/workload/services":
			_ = json.NewEncoder(w).Encode(map[string]any{"services": []any{map[string]any{"id": service, "service": serviceName, "protocol": protocol, "endpoint": map[string]any{"hostname": managedHostname, "port": port, "public": true}}}})
		case strings.HasSuffix(r.URL.Path, "/run"):
			// retain the managed port through fixture and owner IPC startup.
			// the native owner binds it immediately after resolving this run.
			releasePort.Do(func() { _ = allocated.Close() })
			_ = json.NewEncoder(w).Encode(controlv1.ServiceSelection{ServiceId: service, ServiceRunId: serviceRun, RunNumber: 1,
				Protocol: controlv1.ServiceProtocol(protocol), TrustRevision: trustRevision, ExpiresAt: time.Now().Add(time.Minute), Subject: current.Subject,
				Endpoint: &controlv1.ServiceEndpoint{Hostname: managedHostname, Port: port, Public: true}, PairReady: &native.Ready})
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
			pair.ExpiresAt = minTimeForFixture(pair.ExpiresAt, current.LeaseExpiresAt)
			if pair.PublisherPreparedUntil != nil {
				pair.PublisherPreparedUntil = new(minTimeForFixture(*pair.PublisherPreparedUntil, pair.ExpiresAt))
			}
			if requested.Action == "renew" {
				_ = json.NewEncoder(w).Encode(controlv1.ConnectorPeerPairRenewal{Pair: pair, RunValidUntil: pair.ExpiresAt,
					Protocol: controlv1.ServiceProtocol(protocol), TrustRevision: trustRevision,
					Endpoint: controlv1.ServiceEndpoint{Hostname: managedHostname, Port: port, Public: true},
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
			_ = json.NewEncoder(w).Encode(controlv1.VisitorTokenResponse{Resource: requested.Resource, Hostname: managedHostname, Port: port, ServiceTrustRevision: &trustRevision, VisitorPolicyRevision: 1, VisitorToken: "fixture-connector-visitor-token", ExpiresAt: minTimeForFixture(time.Now().Add(time.Minute), current.LeaseExpiresAt)})
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
		borrowedReleaseOnce.Do(func() { close(borrowedRelease) })
		select {
		case <-startupRelease:
		default:
			close(startupRelease)
		}
		authority.Close()
	}()
	server := strings.Replace(authority.URL, "127.0.0.1", "localhost", 1)
	verifier, err := oidc.NewGitHubWorkloadVerifier(server, issuer.Client)
	if err != nil {
		t.Fatal(err)
	}
	verifyAssertion = func(ctx context.Context, raw string) (oidc.WorkloadExecution, error) {
		claims, err := verifier.Verify(ctx, raw)
		return oidc.WorkloadExecution{GitHub: &claims, ExpiresAt: claims.ExpiresAt, AssertionDigest: claims.AssertionDigest}, err
	}
	if googleConfig {
		verifier, err := oidc.NewWorkloadVerifier(server, issuer.Client)
		if err != nil {
			t.Fatal(err)
		}
		trust := oidc.WorkloadTrust{Provider: "google", Issuer: config.GoogleWorkloadIssuer, JWKSURL: config.GoogleWorkloadJWKS, Audience: server, Claims: map[string]string{"sub": "112010400000000710080"}}
		verifyAssertion = func(ctx context.Context, raw string) (oidc.WorkloadExecution, error) {
			return verifier.Verify(ctx, trust, raw)
		}
	}
	target := "http://unused.invalid:3000"
	targetDefinition := map[string]any{"type": "address", "address": target}
	if protocol == "kubernetes" {
		targetDefinition = map[string]any{"type": "eks", "cluster": "fixture", "region": "us-east-1"}
	}
	workloadPolicy := map[string]any{"github": map[string]any{"workflow": ".github/workflows/test.yml", "branch": "main", "events": []string{"push"}}, "services": []string{serviceName}}
	if startup == "borrowed-refresh" {
		workloadPolicy["token"] = map[string]any{"file": "assertion"}
	}
	if googleConfig {
		delete(workloadPolicy, "github")
		workloadPolicy["google"] = map[string]any{"service_account": "112010400000000710080"}
		if startup == "config-google-token-file" {
			workloadPolicy["token"] = map[string]any{"file": "assertion"}
		} else if startup == "config-google-token-env" {
			workloadPolicy["token"] = map[string]any{"env": "FIXTURE_GOOGLE_ASSERTION"}
		}
	}
	configuration := map[string]any{"version": 1, "tnl": map[string]any{"server": server, "team": team, "publisher_groups": map[string]any{"remote": map[string]any{"public": true}}, "services": map[string]any{serviceName: map[string]any{"publisher_group": "remote", "protocol": protocol, "target": targetDefinition}}, "workloads": map[string]any{"test": workloadPolicy}}}
	if startup == "action-wrong-provider" {
		configuration["tnl"].(map[string]any)["workloads"] = map[string]any{"test": map[string]any{"fly": map[string]any{"app": "fixture", "org": "example"}, "services": []string{serviceName}}}
	}
	data, _ := json.Marshal(configuration)
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://github.com/fixture/shop.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v %s", err, output)
		}
	}
	// the SDK resolves its native package by platform and matching version.
	// supply this test's built binary without installing an unrelated ORM.
	installSDKNativePackage(t, root, binary)
	caPath := filepath.Join(root, "root.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "TNL_") && !strings.HasPrefix(value, "OTEL_") && !strings.HasPrefix(value, "ACTIONS_ID_TOKEN_REQUEST_") && !strings.HasPrefix(value, "GITHUB_ACTIONS=") {
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
		if bytes.Contains(body, []byte("application-only")) || bytes.Contains(body, []byte("streamed-body")) || bytes.Contains(body, []byte("PRIVATE KEY")) || bytes.Contains(body, []byte("action-private-runtime-bearer")) || bytes.Contains(body, []byte("/action-provider-token")) {
			t.Error("trace exported private application data")
		}
		for _, proof := range privateActionProofs() {
			if bytes.Contains(body, []byte(proof)) {
				t.Error("trace exported a private Action proof")
			}
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
	initialClaims := githubtest.Claims(server, time.Now())
	if googleConfig {
		initialClaims = map[string]any{"iss": config.GoogleWorkloadIssuer, "aud": server, "sub": "112010400000000710080", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	}
	var initialProofExpiry time.Time
	if strings.HasSuffix(startup, "-refresh") {
		initialProofExpiry = time.Now().Add(35 * time.Second).Truncate(time.Second)
		initialClaims["exp"] = initialProofExpiry.Unix()
	}
	if strings.HasPrefix(startup, "action-") {
		initialProofExpiry = time.Now().Add(15 * time.Second).Truncate(time.Second)
		initialClaims["exp"] = initialProofExpiry.Unix()
		providerAudience = scope.Audience
	}
	assertion := issuer.Sign(t, initialClaims)
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
	if strings.HasPrefix(startup, "action-") {
		proofMu.Lock()
		actionProofs = append(actionProofs, assertion)
		proofMu.Unlock()
	}
	if googleConfig {
		if startup == "config-google-token-file" {
			if err := os.WriteFile(filepath.Join(root, "assertion"), []byte(assertion), 0600); err != nil {
				t.Fatal(err)
			}
		} else if startup == "config-google-token-env" {
			env = append(env, "FIXTURE_GOOGLE_ASSERTION="+assertion)
		}
	}
	if strings.HasPrefix(startup, "javascript") || strings.HasPrefix(startup, "python") {
		manifest := workloadmanifest.Manifest{Schema: 1, Server: scope.Server, Team: scope.TeamID, ProjectKey: scope.ProjectKey, SourceFingerprint: scope.SourceID, ProjectLabel: scope.ProjectLabel,
			Workloads: map[string]workloadmanifest.Workload{"test": {Provider: "github", Services: []string{serviceName}, MaxDurationSeconds: 3600, Acquisition: workloadmanifest.Acquisition{Method: "github-actions", Audience: scope.Server}}}, Services: map[string]string{serviceName: protocol}}
		if strings.HasSuffix(startup, "-refresh") {
			policy := manifest.Workloads["test"]
			policy.MaxDurationSeconds = 0
			manifest.Workloads["test"] = policy
		}
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
		if strings.HasSuffix(startup, "-refresh") {
			cancel()
			ctx, cancel = context.WithTimeout(t.Context(), 90*time.Second)
		}
		defer cancel()
		child := exec.CommandContext(ctx, "node", fixture)
		if startup == "javascript-copies" {
			child = exec.CommandContext(ctx, "node", fixture, "copies")
		}
		child.Env = append(slices.Clone(env), "TMPDIR="+root)
		if startup == "javascript-provider" {
			child.Args = append(child.Args, "provider")
		}
		if startup == "javascript-refresh" {
			child.Args = append(child.Args, "refresh")
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
			if startup == "python-refresh" {
				child.Args = append(child.Args, "refresh")
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
		initialHandle, err := connectorruntime.ReadHandle(owner.ConnectionHandle)
		if err != nil {
			t.Fatal(err)
		}
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
		if strings.HasSuffix(startup, "-refresh") {
			if !lines.Scan() || lines.Text() != "streaming" {
				t.Fatal("SDK did not open the original stream")
			}
			freshClaims := githubtest.Claims(server, time.Now())
			freshClaims["jti"] = "background-refreshed-proof"
			file := filepath.Join(root, "assertion")
			if err := os.WriteFile(file+".next", []byte(issuer.Sign(t, freshClaims)), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(file+".next", file); err != nil {
				t.Fatal(err)
			}
			select {
			case <-refreshedProof:
			case <-ctx.Done():
				t.Fatal("quiet native owner did not refresh its proof")
			}
			timer := time.NewTimer(time.Until(initialProofExpiry.Add(time.Second)))
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				t.Fatal("original proof deadline did not elapse")
			}
			close(refreshAfter)
			_, _ = io.WriteString(input, "refreshed\n")
			if !lines.Scan() || lines.Text() != "retained" {
				t.Fatal("original SDK stream did not survive background refresh")
			}
			afterOwner, after := readSDKSelection(t, root, serviceName)
			if owner != afterOwner || first.TransportID != after.TransportID || first.Port != after.Port || !after.ExpiresAt.After(first.ExpiresAt) || refreshStreams.Load() != 1 || exchangeAttempts.Load() != 2 {
				t.Fatal("background refresh replaced the owner, stream or transport")
			}
			afterHandle, err := connectorruntime.ReadHandle(afterOwner.ConnectionHandle)
			nonexpiring := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
			if err != nil || !initialHandle.ExpiresAt.Equal(nonexpiring) || !afterHandle.ExpiresAt.Equal(nonexpiring) || initialHandle.URL != afterHandle.URL || initialHandle.Key != afterHandle.Key {
				t.Fatal("SDK-owned handle did not retain its nonexpiring capability", err)
			}
			t.Logf("native SDK handle: before=%s after=%s; connection before=%s after=%s", initialHandle.ExpiresAt.Format(time.RFC3339Nano), afterHandle.ExpiresAt.Format(time.RFC3339Nano), first.ExpiresAt.Format(time.RFC3339Nano), after.ExpiresAt.Format(time.RFC3339Nano))
			t.Log("quiet native owner reread a rotating file; original SDK stream crossed proof expiry without a request callback, owner replacement or replay")
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
	startRequest := connectorruntime.StartRequest{Schema: 1, Context: scope, Assertion: assertion}
	if startup == "borrowed-refresh" {
		file := filepath.Join(root, "assertion")
		if err := os.WriteFile(file, []byte(assertion), 0600); err != nil {
			t.Fatal(err)
		}
		// exercise normal CLI acquisition and native refresh-source selection.
		startRequest.Assertion = ""
	}
	if googleConfig && startup != "config-google-caller-assertion" {
		// leave the assertion empty to exercise config acquisition, not the SDK
		// manifest path or the caller-supplied assertion fast path.
		startRequest.Assertion = ""
	}
	request, _ := json.Marshal(startRequest)
	if strings.HasPrefix(startup, "action-") && startup != "action-static" {
		// proposed action-only private stdin contract. keep runtime credentials
		// out of workload manifests, ordinary SDK inputs and the owner's env.
		audience := scope.Audience
		if startup == "action-wrong-audience" {
			audience = "https://wrong.example.test"
		}
		request, _ = json.Marshal(map[string]any{"schema": 1, "context": scope, "assertion": assertion, "github_actions_refresh": map[string]string{
			"audience": audience, "request_url": server + "/action-provider-token?keep=yes&audience=wrong", "request_token": "action-private-runtime-bearer",
		}})
	}
	var state connectorruntime.Status
	startArgs := []string{"start", "--directory", root, "--workload", "test", "--runner-temp", root}
	if startup == "action-wrong-audience" || startup == "action-wrong-provider" {
		rejectMismatchedActionRefresh(t, binary, slices.Clone(env), startArgs, request)
		authorityMu.Lock()
		defer authorityMu.Unlock()
		if len(controlCalls) != 0 || providerCalls.Load() != 0 {
			t.Fatal("mismatched Action refresh performed acquisition or control work")
		}
		return nil
	}
	if protocol == "kubernetes" {
		path := filepath.Join(root, "cluster-token")
		if err := os.WriteFile(path, []byte("fixture-cluster-token"), 0o600); err != nil {
			t.Fatal(err)
		}
		startArgs = append(startArgs, "--kube-token-file", path, "--namespace", "runtime-test")
	}
	if startup != "caller-prepared" && startup != "borrowed-refresh" && !strings.HasPrefix(startup, "action-") && !googleConfig {
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
	if startup == "borrowed-refresh" {
		before, err := connectorruntime.ReadHandle(state.ConnectionHandle)
		if err != nil || !before.ExpiresAt.Equal(initialProofExpiry) {
			t.Fatal("CLI-started workload owner did not issue the finite proof deadline", before.ExpiresAt, initialProofExpiry, err)
		}
		type externalClient struct {
			name        string
			wait        func() error
			input       io.WriteCloser
			lines       *bufio.Scanner
			diagnostics *bytes.Buffer
		}
		var clients []externalClient
		ctx, cancel := context.WithTimeout(t.Context(), 70*time.Second)
		defer cancel()
		for _, language := range []string{"javascript", "python"} {
			fixture, _ := filepath.Abs("../../../packages/ts/test/fixtures/connections/borrowed-expiry.ts")
			child := exec.CommandContext(ctx, "node", fixture)
			child.Env = append(slices.Clone(env), "TNL_CONNECTION_HANDLE="+state.ConnectionHandle)
			if language == "python" {
				python, _ := filepath.Abs("../../../packages/py/.venv/bin/python")
				fixture, _ := filepath.Abs("../../../packages/py/tests/native_borrowed_expiry.py")
				source, _ := filepath.Abs("../../../packages/py/src")
				child = exec.CommandContext(ctx, python, fixture, binary)
				child.Env = append(slices.Clone(env), "TNL_CONNECTION_HANDLE="+state.ConnectionHandle, "PYTHONPATH="+source)
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
			diagnostics := new(bytes.Buffer)
			child.Stderr = diagnostics
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			clients = append(clients, externalClient{language, sync.OnceValue(child.Wait), input, bufio.NewScanner(output), diagnostics})
		}
		defer func() {
			for _, child := range clients {
				_, _ = io.WriteString(child.input, "stop\n")
				_ = child.input.Close()
				_ = child.wait()
			}
		}()
		for _, child := range clients {
			if !child.lines.Scan() || child.lines.Text() != "cold" {
				t.Fatal(child.name, "did not cache external IPC")
			}
		}
		freshClaims := githubtest.Claims(server, time.Now())
		freshClaims["jti"] = "borrowed-refreshed-proof"
		file := filepath.Join(root, "assertion")
		if err := os.WriteFile(file+".next", []byte(issuer.Sign(t, freshClaims)), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(file+".next", file); err != nil {
			t.Fatal(err)
		}
		select {
		case <-refreshedProof:
		case <-ctx.Done():
			t.Fatal("borrowed owner did not refresh its proof")
		}
		<-time.After(time.Until(initialProofExpiry.Add(-time.Second)))
		blockBorrowed.Store(true)
		_, _ = io.WriteString(clients[0].input, "cross\n")
		select {
		case <-borrowedCrossing:
		case <-ctx.Done():
			t.Fatal("TypeScript did not enter its crossing preparation")
		}
		<-time.After(time.Until(initialProofExpiry.Add(300 * time.Millisecond)))
		blockBorrowed.Store(false)
		borrowedReleaseOnce.Do(func() { close(borrowedRelease) })
		for _, child := range clients {
			t.Run(child.name, func(t *testing.T) {
				_, _ = io.WriteString(child.input, "after\nstop\n")
				_ = child.input.Close()
				retained := child.lines.Scan() && child.lines.Text() == "retained"
				err := child.wait()
				if err != nil || !retained {
					t.Fatalf("borrowed SDK did not prepare across renewed expiry: %v\n%s", err, child.diagnostics.String())
				}
			})
		}
		after, err := connectorruntime.ReadHandle(state.ConnectionHandle)
		expected := before
		expected.ExpiresAt = after.ExpiresAt
		if err != nil || !after.ExpiresAt.After(before.ExpiresAt) || expected != after {
			t.Fatal("borrowed handle did not advance in place", err)
		}
		var current connectorruntime.Status
		if err := connectorruntime.Call(ctx, state.ConnectionHandle, "status", connectorruntime.Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest}, &current); err != nil || current.PID != state.PID {
			t.Fatal("closing borrowed SDK clients stopped the original native owner", err)
		}
		t.Logf("native borrowed handle: before=%s after=%s status=%s; same PID=%d, URL, key, path", before.ExpiresAt.Format(time.RFC3339Nano), after.ExpiresAt.Format(time.RFC3339Nano), current.ExpiresAt.Format(time.RFC3339Nano), current.PID)
		return nil
	}
	if state.PID == os.Getpid() || state.State != "ready" {
		t.Fatal("no detached connector owner")
	}
	if googleConfig {
		var prepared connectorruntime.Prepared
		if err := connectorruntime.ReadJSON(bytes.NewReader(call(nil, "read", "--handle", state.ConnectionHandle, "--service", serviceName)), &prepared); err != nil {
			t.Fatal(err)
		}
		if err := connectorruntime.ValidatePrepared(prepared, serviceName); err != nil {
			t.Fatal(err)
		}
		call(nil, "stop", "--handle", state.ConnectionHandle)
		state.ConnectionHandle = ""
		if !revoked.Load() || exchangeAttempts.Load() != 2 {
			t.Fatal("Google config owner did not recover signed exchange and revoke on stop")
		}
		t.Logf("%s started a real owner from config with a verified Google assertion and no manifest", startup)
		return nil
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
	if strings.HasPrefix(startup, "action-") {
		qualifyActionBackgroundRefresh(t, actionRefreshFixture{
			root: root, state: state, prepared: prepared, roots: roots, expiry: initialProofExpiry, mode: startup,
			providerCalls: &providerCalls, redirectedCalls: &redirectedProviderCalls, streams: &refreshStreams,
			refreshed: refreshedProof, release: refreshAfter, providerCanceled: providerCanceled,
			call: call, privateProofs: privateActionProofs,
			inspect: func() (map[string]int, authorityv1.WorkloadSession, int) {
				authorityMu.Lock()
				defer authorityMu.Unlock()
				var current authorityv1.WorkloadSession
				for _, session := range sessions {
					current = session.WorkloadSession
				}
				return maps.Clone(controlCalls), current, len(ownerKeys)
			},
		})
		return nil
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
	if prepared.Schema != 1 || prepared.ProjectRuntime.Services[serviceName].Hostname != managedHostname || !prepared.ProjectRuntime.Services[serviceName].Public {
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

func minTimeForFixture(values ...time.Time) time.Time {
	until := values[0]
	for _, value := range values[1:] {
		if value.Before(until) {
			until = value
		}
	}
	return until
}
