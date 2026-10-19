package tcpconnect

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/tnldotdev/tnl/internal/authorityapi"
	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type lifecycleDatabaseFixture struct {
	database       *controlstate.Database
	inspect        *sql.DB
	client         *controlclient.Client
	authority      *authorityclient.Client
	profile        *clientstate.Store
	identity, team string
	service        controlv1.PrivateService
}

func newLifecycleDatabaseFixture(t *testing.T, intercept func(http.ResponseWriter, *http.Request, http.Handler)) *lifecycleDatabaseFixture {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "private-lifecycle")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	inspect, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inspect.Close() })
	session, err := controltest.Session(ctx, database, "example.test", time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := controlapi.NewHandler(controlapi.Config{}, database, database, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if intercept != nil {
			intercept(w, r, handler)
		} else {
			handler.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(server.Close)
	if _, err := authorityapi.Register(handler, authorityapi.Config{ControlURL: server.URL}, database); err != nil {
		t.Fatal(err)
	}
	client, err := controlclient.New(server.URL, server.Client(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityclient.New(server.URL, server.Client(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	state, err := clientstate.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	profile, err := state.Server(ctx, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	team := session.Identity.Memberships[0].TeamID
	service, err := client.CreatePrivateService(ctx, team, "database", "database")
	if err != nil {
		t.Fatal(err)
	}
	return &lifecycleDatabaseFixture{database: database, inspect: inspect, client: client, authority: authority, profile: profile, identity: session.Identity.Identity.ID, team: team, service: service}
}

func (f *lifecycleDatabaseFixture) reservations(t *testing.T) int {
	t.Helper()
	var count int
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.private_connector_sessions WHERE revoked_at IS NULL AND expires_at>now()`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestIntegrationPrivateConnectorReleasesLowCapacityReservations(t *testing.T) {
	var failTrust atomic.Bool
	var trustCalls atomic.Int64
	var pairCalls atomic.Int64
	failTrust.Store(true)
	f := newLifecycleDatabaseFixture(t, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/ingress-assignments") {
			pairCalls.Add(1)
		}
		if failTrust.Load() && strings.HasSuffix(r.URL.Path, "/transport-trust") {
			trustCalls.Add(1)
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"code":"unavailable"}`)
			return
		}
		next.ServeHTTP(w, r)
	})
	leases := make(map[string]controlstate.IngressLeaseIdentity)
	for i, id := range []string{"ingress-a", "ingress-b"} {
		lease, err := f.database.RegisterIngress(t.Context(), controlstate.IngressRegistration{IngressID: id, IngressRunID: connectorID(t, opaqueid.IngressRunPrefix), ProtocolVersion: 1,
			ConnectionCapacity: 1, PrivateConnectorAddress: fmt.Sprintf("127.0.0.1:%d", 9441+i), PrivateConnectorTLSServerName: "ingress.example.test"}, time.Now(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		leases[id] = lease.IngressLeaseIdentity
	}
	control, err := NewControl(f.client, f.profile, f.identity)
	if err != nil {
		t.Fatal(err)
	}
	adapter := control.(*controlAdapter)
	t.Cleanup(func() { _ = adapter.Close() })
	device, err := adapter.PrivateConnectorDevice(t.Context(), f.identity)
	if err != nil {
		t.Fatal(err)
	}
	// a pending sibling occupies its ingress's entire capacity. repeated
	// failure must reserve only the requested slot on the other ingress.
	for range 8 {
		if _, err := adapter.PrivateConnectorAssignment(t.Context(), f.service.Id, device.ID, 0); !errors.Is(err, controlclient.ErrUnavailable) {
			t.Fatalf("trust failure: %v", err)
		}
		if count := f.reservations(t); count != 1 {
			t.Fatalf("single-slot refresh leaked reservations: %d", count)
		}
	}
	// expire the pending sibling in both the saved response and PostgreSQL.
	adapter.mu.Lock()
	pending := adapter.pairs[assignmentKey{f.service.Id, device.ID}].pending[1]
	pending.ExpiresAt = time.Now().Add(-time.Second)
	adapter.mu.Unlock()
	if _, err := f.inspect.ExecContext(t.Context(), `UPDATE control.private_connector_sessions SET created_at=now()-interval '2 minutes',expires_at=now()-interval '1 second' WHERE id=$1`, pending.ConnectorSessionId); err != nil {
		t.Fatal(err)
	}
	failTrust.Store(false)
	healthy, err := adapter.PrivateConnectorAssignment(t.Context(), f.service.Id, device.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	var revoked bool
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT revoked_at IS NOT NULL FROM control.private_connector_sessions WHERE id=$1`, pending.ConnectorSessionId).Scan(&revoked); err != nil || !revoked {
		t.Fatalf("expired pending assignment not released: %v", err)
	}
	nonce, _ := tunnelv1.NewConnectorSessionNonce()
	hello := tunnelv1.PrivateConnectorSessionHello{ProtocolVersion: 1, Kind: "private_connector_session", PrivateServiceID: f.service.Id, SessionID: healthy.SessionID,
		Credential: healthy.Credential, DeviceID: device.ID, IdentityID: device.IdentityID, Nonce: nonce}
	digest, _ := tunnelv1.PrivateConnectorHelloDigest(hello)
	hello.Signature = ed25519.Sign(device.SigningKey, digest)
	if _, err := f.database.AuthenticatePrivateConnector(t.Context(), leases[healthy.IngressID], hello, netip.MustParseAddr("127.0.0.1"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.RenewIngress(t.Context(), controlstate.IngressRenewal{IngressLeaseIdentity: leases[healthy.IngressID], ReportedConnections: 1}, time.Now(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if healthy.IngressID != "ingress-a" {
		t.Fatalf("expected ingress-a to be full: %s", healthy.IngressID)
	}
	var createdOnHealthy int
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.private_connector_sessions WHERE assigned_ingress_id=$1`, healthy.IngressID).Scan(&createdOnHealthy); err != nil {
		t.Fatal(err)
	}
	failTrust.Store(true)
	for range 8 {
		before := trustCalls.Load()
		if _, err := adapter.PrivateConnectorAssignment(t.Context(), f.service.Id, device.ID, 0); !errors.Is(err, controlclient.ErrUnavailable) {
			t.Fatalf("renewal failed before trust lookup: %v", err)
		}
		if trustCalls.Load() != before+1 {
			t.Fatal("full healthy ingress blocked the failed slot before its trust lookup")
		}
		if count := f.reservations(t); count != 1 {
			t.Fatalf("failed renewal leaked reservations: %d", count)
		}
		if err := f.inspect.QueryRowContext(t.Context(), `SELECT revoked_at IS NOT NULL FROM control.private_connector_sessions WHERE id=$1`, healthy.SessionID).Scan(&revoked); err != nil || revoked {
			t.Fatalf("healthy sibling revoked during recovery: %v", err)
		}
		var count int
		if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.private_connector_sessions WHERE assigned_ingress_id=$1`, healthy.IngressID).Scan(&count); err != nil || count != createdOnHealthy {
			t.Fatalf("refresh allocated an unused healthy-ingress reservation: before=%d after=%d err=%v", createdOnHealthy, count, err)
		}
	}
	if pairCalls.Load() != 1 {
		t.Fatalf("refresh allocated %d startup pairs", pairCalls.Load())
	}
	failTrust.Store(false)
	recovered, err := adapter.PrivateConnectorAssignment(t.Context(), f.service.Id, device.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.IngressID != "ingress-b" || recovered.TransportTLS == nil || recovered.TransportTLS.InsecureSkipVerify || recovered.TransportTLS.ServerName != recovered.Endpoint.ServerName {
		t.Fatal("single-slot recovery lost distinct ingress or exact endpoint trust")
	}
	nonce, _ = tunnelv1.NewConnectorSessionNonce()
	hello.SessionID, hello.Credential, hello.Nonce = recovered.SessionID, recovered.Credential, nonce
	digest, _ = tunnelv1.PrivateConnectorHelloDigest(hello)
	hello.Signature = ed25519.Sign(device.SigningKey, digest)
	if _, err := f.database.AuthenticatePrivateConnector(t.Context(), leases[recovered.IngressID], hello, netip.MustParseAddr("127.0.0.1"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.AuthenticatePrivateConnector(t.Context(), leases[recovered.IngressID], hello, netip.MustParseAddr("127.0.0.1"), time.Now()); !errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		t.Fatalf("recovered credential was not single-use: %v", err)
	}
	if err := adapter.ReleasePrivateConnectorAssignment(t.Context(), recovered.SessionID); err != nil {
		t.Fatal(err)
	}
	if f.reservations(t) != 1 {
		t.Fatal("closing recovered slot revoked the healthy sibling")
	}
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT revoked_at IS NOT NULL FROM control.private_connector_sessions WHERE id=$1`, healthy.SessionID).Scan(&revoked); err != nil || revoked {
		t.Fatalf("closing recovered slot revoked its healthy sibling: %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	if count := f.reservations(t); count != 0 {
		t.Fatalf("shutdown retained %d reservations", count)
	}
	if _, err := f.database.RenewIngress(t.Context(), controlstate.IngressRenewal{IngressLeaseIdentity: leases[healthy.IngressID]}, time.Now(), time.Minute); err != nil {
		t.Fatal(err)
	}
	// Serve must close an optional reservation owner even if neither path can
	// become ready. this exercises cancellation while its workers are retrying.
	failTrust.Store(true)
	runner, err := NewControl(f.client, f.profile, f.identity)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	before := trustCalls.Load()
	go func() {
		done <- Serve(ctx, listener, Config{Control: runner, PrivateServiceID: f.service.Id, IdentityID: f.identity, Protocol: "tcp", TrustRevision: 1, ManagedTLS: f.service.ManagedTls, ServiceTLS: &tls.Config{MinVersion: tls.VersionTLS12}})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for trustCalls.Load() < before+4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("failed connector did not join")
	}
	if trustCalls.Load() < before+4 || f.reservations(t) != 0 {
		t.Fatal("Serve abandoned reservations while shutting down failed paths")
	}
}

func TestIntegrationPrivatePublisherRecoversCommittedLostResponses(t *testing.T) {
	var mu sync.Mutex
	var preparationKeys []string
	var bindingBodies [][]byte
	f := newLifecycleDatabaseFixture(t, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		preparing, binding := r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/runs"), strings.HasSuffix(r.URL.Path, "/start")
		if !preparing && !binding {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		mu.Lock()
		if preparing {
			preparationKeys = append(preparationKeys, r.Header.Get("Idempotency-Key"))
		} else {
			bindingBodies = append(bindingBodies, body)
		}
		attempt := len(preparationKeys)
		if binding {
			attempt = len(bindingBodies)
		}
		mu.Unlock()
		committed := httptest.NewRecorder()
		next.ServeHTTP(committed, r)
		if committed.Code >= 200 && committed.Code < 300 && attempt <= 3 {
			// the real handler has committed PostgreSQL before the connection
			// disappears; recovery must query that exact key/binding again.
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		for k, values := range committed.Header() {
			w.Header()[k] = values
		}
		w.WriteHeader(committed.Code)
		_, _ = w.Write(committed.Body.Bytes())
	})
	leases := make(map[string]controlstate.RelayLeaseIdentity)
	for _, id := range []string{"relay-a", "relay-b"} {
		lease, err := f.database.RegisterRelay(t.Context(), controlstate.RelayRegistration{RelayID: id, RelayServiceID: id, RelayRunID: connectorID(t, opaqueid.RelayRunPrefix),
			ProtocolVersion: 1, RelayAddress: id + ".example.test:443", TLSServerName: id + ".example.test", InternalRelayAddress: "127.0.0.1:9443", ConnectionCapacity: 2, StreamCapacity: 4}, time.Now(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		leases[id] = lease.RelayLeaseIdentity
	}
	enrollment, err := f.client.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: f.team, PrivateServiceId: &f.service.Id, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled, Name: "publisher"})
	if err != nil {
		t.Fatal(err)
	}
	public, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := f.authority.RedeemPublisherEnrollment(t.Context(), enrollment.EnrollmentKey, public)
	if err != nil {
		t.Fatal(err)
	}
	access := func(ctx context.Context) (string, error) {
		return f.authority.ExchangePublisherAssertion(ctx, identity.ClientId, identity.GrantId, identity.KeyId, signing)
	}
	token, err := access(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var prep controlv1.PrivateServiceRunPreparation
	for attempt := range 4 {
		prep, err = f.client.PreparePrivateServiceRun(t.Context(), f.service.Id, "stable-preparation", token)
		if err == nil {
			break
		}
		if attempt == 3 && err != nil {
			t.Fatal(err)
		}
	}
	var setup controlv1.PrivateServiceRunSetup
	for attempt := range 4 {
		setup, err = f.client.StartManagedServiceRun(t.Context(), f.service.Id, prep.PrivateRunId, token, prep.RunNumber)
		if err == nil {
			break
		}
		if attempt == 3 && err != nil {
			t.Fatal(err)
		}
	}
	if len(setup.PublisherConnections) != 2 || prep.CertificatePlan == nil || prep.Hostname != f.service.ManagedTls.Hostname || prep.ServicePort != f.service.ManagedTls.Port {
		t.Fatal("recovery changed endpoint or assignments")
	}
	var runs, number int
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*),max(run_number) FROM control.private_service_runs WHERE private_service_id=$1`, f.service.Id).Scan(&runs, &number); err != nil || runs != 1 || number != 1 {
		t.Fatalf("recovery created another run: runs=%d number=%d err=%v", runs, number, err)
	}
	mu.Lock()
	keys := append([]string(nil), preparationKeys...)
	bodies := append([][]byte(nil), bindingBodies...)
	mu.Unlock()
	if len(keys) != 4 || len(bodies) != 4 {
		t.Fatalf("uncertain operation was not recovered through repeated loss: prepare=%d bind=%d", len(keys), len(bodies))
	}
	for _, key := range keys {
		if key != keys[0] {
			t.Fatal("preparation retry replaced the idempotency key")
		}
	}
	for _, body := range bodies {
		if !bytes.Equal(body, bodies[0]) {
			t.Fatal("start retry replaced its prepared run")
		}
	}
	var bound controlv1.StartManagedServiceRunJSONRequestBody
	if err := json.Unmarshal(bodies[0], &bound); err != nil || bound.RunNumber != prep.RunNumber {
		t.Fatal("PostgreSQL did not retain the recovered run", err)
	}
	// a distinct invocation conflicts with the live run. it must return that
	// permanent result, rather than treating every conflict as response loss.
	conflict, stopConflict := context.WithTimeout(t.Context(), time.Second)
	defer stopConflict()
	if _, err := f.client.PreparePrivateServiceRun(conflict, f.service.Id, "different-invocation", token); !errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatalf("a distinct preparation did not return its permanent conflict: %v", err)
	}
	if err := f.client.ClosePrivateServiceRun(t.Context(), f.service.Id, setup.PrivateRunId, credentials.PublishRunToken(setup.RunToken)); err != nil {
		t.Fatal(err)
	}
}
