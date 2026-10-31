package public

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// publisher run recovery is independent of the retired native ingress path.
// retain its committed-response-loss proof at the serving API boundary.
func TestIntegrationPrivatePublisherRecoversCommittedLostResponses(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "publisher_run_retry")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	inspect, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inspect.Close(context.Background()) })
	owner, err := controltest.Session(ctx, database, "example.test", time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{}, database, database, nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var preparationKeys []string
	var bindingBodies [][]byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		preparing := r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/runs")
		binding := r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/start")
		if !preparing && !binding {
			handler.ServeHTTP(w, r)
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
		handler.ServeHTTP(committed, r)
		if committed.Code >= 200 && committed.Code < 300 && attempt <= 3 {
			// PostgreSQL committed before the socket disappears. retries must
			// recover this exact preparation key and prepared run binding.
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		for key, values := range committed.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(committed.Code)
		_, _ = w.Write(committed.Body.Bytes())
	}))
	t.Cleanup(server.Close)
	if _, err := controlauthority.Register(handler, controlauthority.Config{ControlURL: server.URL}, database); err != nil {
		t.Fatal(err)
	}
	client, err := clientcontrol.New(server.URL, server.Client(), owner.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(server.URL, server.Client(), owner.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	team := owner.Identity.Memberships[0].TeamID
	service, err := client.CreateService(ctx, team, "database", "database")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"relay-a", "relay-b"} {
		run, err := opaqueid.New(opaqueid.RelayRunPrefix)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.RegisterRelay(ctx, controlstate.RelayRegistration{RelayID: id, RelayServiceID: id, RelayRunID: run,
			ProtocolVersion: 1, RelayAddress: id + ".example.test:443", TLSServerName: id + ".example.test", InternalRelayAddress: "127.0.0.1:9443", ConnectionCapacity: 2, StreamCapacity: 4}, time.Now(), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	enrollment, err := client.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: team, ServiceId: &service.Id, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled, Name: "publisher"})
	if err != nil {
		t.Fatal(err)
	}
	public, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authority.RedeemPublisherEnrollment(ctx, enrollment.EnrollmentKey, public)
	if err != nil {
		t.Fatal(err)
	}
	token, err := authority.ExchangePublisherAssertion(ctx, identity.ClientId, identity.GrantId, identity.KeyId, signing)
	if err != nil {
		t.Fatal(err)
	}
	var prep controlv1.ServiceRunPreparation
	for attempt := range 4 {
		prep, err = client.PrepareServiceRun(ctx, service.Id, "stable-preparation", token, controlv1.ServiceRunDeclaration{Protocol: controlv1.Tcp, TrustRevision: 1})
		if err == nil {
			break
		}
		if attempt == 3 {
			t.Fatal(err)
		}
	}
	var setup controlv1.ServiceRunSetup
	for attempt := range 4 {
		setup, err = client.StartServiceRun(ctx, service.Id, prep.ServiceRunId, token, prep.RunNumber)
		if err == nil {
			break
		}
		if attempt == 3 {
			t.Fatal(err)
		}
	}
	if len(setup.PublisherConnections) != 2 || prep.CertificatePlan == nil || prep.Hostname != service.Endpoint.Hostname || prep.ServicePort != service.Endpoint.Port {
		t.Fatal("recovery changed endpoint or assignments")
	}
	var runs, number int
	if err := inspect.QueryRow(ctx, `SELECT count(*),max(run_number) FROM control.service_runs WHERE service_id=$1`, service.Id).Scan(&runs, &number); err != nil || runs != 1 || number != 1 {
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
		if key != "stable-preparation" {
			t.Fatal("preparation retry replaced the idempotency key")
		}
	}
	for _, body := range bodies {
		if !bytes.Equal(body, bodies[0]) {
			t.Fatal("start retry replaced its prepared run")
		}
	}
	var bound controlv1.StartServiceRunJSONRequestBody
	if err := json.Unmarshal(bodies[0], &bound); err != nil || bound.RunNumber != prep.RunNumber {
		t.Fatal("PostgreSQL did not retain the recovered run", err)
	}
	// another invocation is a permanent conflict, not ambiguous response loss.
	conflict, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if _, err := client.PrepareServiceRun(conflict, service.Id, "different-invocation", token, controlv1.ServiceRunDeclaration{Protocol: controlv1.Tcp, TrustRevision: 1}); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatalf("a distinct preparation did not return its permanent conflict: %v", err)
	}
	if err := client.CloseServiceRun(ctx, service.Id, setup.ServiceRunId, credentials.ServiceRunToken(setup.RunToken)); err != nil {
		t.Fatal(err)
	}
}
