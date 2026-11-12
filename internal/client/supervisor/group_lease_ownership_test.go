package supervisor

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the real control issuer replaces every earlier replica lease, including one
// minted by the runtime owner. exercise the production runner/callback rather
// than a publication stub, and hold both services at their preparation boundary.
func TestEnvironmentPublisherWorkersKeepRuntimeLease(t *testing.T) {
	job, _, private := kindFixture(t, KindGroup)
	member := *job.GroupMember
	publication := controlv1.EnvironmentPublication{EnvironmentId: member.EnvironmentId, MutationRevision: 7, ConfigurationHash: strings.Repeat("a", 64)}
	assignments := controlv1.EnvironmentPublisherAssignments{Publisher: member, Environment: publication, CertificateStatePlans: []controlv1.CertificatePlan{}}
	services, grants := map[string]controlv1.Service{}, map[string]string{}
	newID := func(prefix string) string {
		t.Helper()
		id, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	for _, name := range []string{"database", "cache"} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		serviceID, grantID := newID(opaqueid.ServicePrefix), newID(opaqueid.PublisherGrantPrefix)
		assignments.Services = append(assignments.Services, controlv1.EnvironmentPublisherAssignment{Service: name, ServiceId: serviceID, GrantId: grantID, TrustRevision: 1, Configuration: controlv1.EnvironmentServicePublication{Protocol: controlv1.ServiceProtocol("tcp"), Target: listener.Addr().String()}})
		services[serviceID] = controlv1.Service{Id: serviceID, Name: name, TeamId: member.TeamId, Enabled: true, Protocol: controlv1.ServiceProtocol("tcp"), TrustRevision: 1, PublisherPool: true, Endpoint: &controlv1.ServiceEndpoint{Hostname: name + ".services.example", Port: 443}}
		grants[grantID] = serviceID
	}
	var mu sync.Mutex
	proofs := map[string]bool{}
	preparations, active := map[string]int{}, map[string]bool{}
	currentLease := ""
	leaseNumber, setupLeases, runtimeStarts, runtimeRenewals, stops, denied, pollsWithSiblings, joined := 0, 0, 0, 0, 0, 0, 0, 0
	observed := make(chan struct{})
	handlersJoined := make(chan struct{})
	var observedOnce sync.Once
	write := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Error(err)
		}
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		verify := func(assertion, scope string) bool {
			proof, err := publisherproof.Verify(assertion, member.PublisherIdentityId, member.KeyId, scope, server.URL+r.URL.Path, private.Public().(ed25519.PublicKey), time.Now())
			if err != nil || proofs[proof.ID] {
				t.Error("invalid or replayed publisher proof")
				w.WriteHeader(http.StatusUnauthorized)
				return false
			}
			proofs[proof.ID] = true
			return true
		}
		issueLease := func() controlv1.EnvironmentPublisherLease {
			leaseNumber++
			// matching control's DELETE-before-INSERT invalidates all previous tokens.
			currentLease = fmt.Sprintf("replica-lease-%d", leaseNumber)
			return controlv1.EnvironmentPublisherLease{AccessToken: currentLease, ExpiresAt: time.Now().Add(12 * time.Second)}
		}
		switch r.URL.Path {
		case "/v1/environment-publishers/verify", "/v1/environment-publishers/lease":
			var proof controlv1.EnvironmentPublisherProof
			if json.NewDecoder(r.Body).Decode(&proof) != nil || proof.EnvironmentId != member.EnvironmentId || proof.PublisherIdentityId != member.PublisherIdentityId || !verify(proof.Assertion, member.EnvironmentId) {
				return
			}
			if strings.HasSuffix(r.URL.Path, "/verify") {
				write(w, member)
			} else {
				setupLeases++
				write(w, issueLease())
			}
		case "/v1/publisher-runtime":
			var request controlv1.PublisherRuntimeRequest
			if json.NewDecoder(r.Body).Decode(&request) != nil || !verify(request.Assertion, publisherproof.RuntimeScope(member.EnvironmentId, string(request.Action), request.ProcessRunId, request.ExpectedEpoch, "")) {
				return
			}
			switch request.Action {
			case controlv1.RuntimeInspect:
				write(w, controlv1.PublisherRuntimeResponse{Epoch: 0})
			case controlv1.RuntimeStop:
				stops++
				write(w, controlv1.PublisherRuntimeResponse{Epoch: 1})
			default:
				if request.Action == controlv1.RuntimeStart {
					runtimeStarts++
				} else {
					runtimeRenewals++
				}
				lease := issueLease()
				write(w, controlv1.PublisherRuntimeResponse{Epoch: 1, LeaseExpiresAt: &lease.ExpiresAt, EnvironmentLease: &lease})
			}
		case "/v1/environment-publishers/assignments", "/v1/environment-publishers/ack":
			if currentLease == "" || r.Header.Get("Authorization") != "Bearer "+currentLease {
				denied++
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if strings.HasSuffix(r.URL.Path, "/assignments") {
				if len(active) == len(assignments.Services) {
					pollsWithSiblings++
					if pollsWithSiblings >= 3 && runtimeRenewals > 0 {
						observedOnce.Do(func() { close(observed) })
					}
				}
				write(w, assignments)
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		case "/v1/publisher-token":
			var request authorityv1.PublisherTokenRequest
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.ClientId != member.PublisherIdentityId || grants[request.GrantId] == "" || !verify(request.ClientAssertion, request.GrantId) {
				return
			}
			write(w, authorityv1.PublisherTokenResponse{AccessToken: "service-" + grants[request.GrantId], GrantId: request.GrantId, TokenType: "Bearer", ExpiresIn: 60})
		case "/v1/publisher/service":
			id := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer service-")
			if service, found := services[id]; found {
				write(w, service)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
			if strings.HasPrefix(r.URL.Path, "/v1/services/") && strings.HasSuffix(r.URL.Path, "/runs") {
				id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/services/"), "/runs")
				var declaration controlv1.ServiceRunDeclaration
				service, found := services[id]
				if !found || r.Header.Get("Authorization") != "Bearer service-"+id || json.NewDecoder(r.Body).Decode(&declaration) != nil || declaration.Environment == nil || *declaration.Environment != publication || declaration.Protocol != service.Protocol || declaration.TrustRevision != service.TrustRevision {
					t.Error("service preparation lost exact authenticated publication or grant")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				preparations[id]++
				active[id] = true
				mu.Unlock()
				<-r.Context().Done()
				mu.Lock()
				delete(active, id)
				joined++
				if joined == len(assignments.Services) {
					close(handlersJoined)
				}
				return
			}
			t.Errorf("unexpected operation %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	job.Server = server.URL
	job.ServerCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	profile, err := database.Server(t.Context(), job.Server)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var result error
	runner := GroupRunner{Discovery: discoveryCall(func(context.Context, publisherdiscovery.Request) (publisherdiscovery.ResolvedTarget, error) {
		t.Error("static assignment invoked discovery")
		return publisherdiscovery.ResolvedTarget{}, ErrScope
	})}
	go func() { defer close(done); result = runner.Serve(ctx, job, profile, private, nil) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("publisher runner did not join")
		}
	}()
	select {
	case <-observed:
	case <-done:
		t.Fatal("publisher exited before both services survived runtime lease renewal", result)
	case <-time.After(25 * time.Second):
		t.Fatal("both production workers did not survive authenticated runtime polls and renewal")
	}
	mu.Lock()
	if setupLeases != 1 || runtimeStarts != 1 || runtimeRenewals == 0 || denied != 0 || len(active) != 2 {
		t.Errorf("competing lease ownership: setup=%d starts=%d renewals=%d denied=%d active=%d", setupLeases, runtimeStarts, runtimeRenewals, denied, len(active))
	}
	for id := range services {
		if preparations[id] != 1 {
			t.Error("lease replacement restarted a production service worker")
		}
	}
	mu.Unlock()
	cancel()
	select {
	case <-done:
		if result != nil {
			t.Fatal(result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publisher runner did not join both service workers")
	}
	select {
	case <-handlersJoined:
	case <-time.After(5 * time.Second):
		t.Fatal("service preparation requests did not observe joined cancellation")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(active) != 0 || joined != 2 || stops != 1 || setupLeases != 1 || denied != 0 {
		t.Fatalf("publisher shutdown or lease ownership changed: active=%d joined=%d stops=%d setup=%d denied=%d", len(active), joined, stops, setupLeases, denied)
	}
}
