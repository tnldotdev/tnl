package stream

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationConnectorRecoversCommittedAssignments(t *testing.T) {
	var mu sync.Mutex
	bodies, results := map[string][][]byte{}, map[string][][]byte{}
	f := newLifecycleDatabaseFixture(t, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method != http.MethodPost || !(strings.HasSuffix(r.URL.Path, "/ingress-assignments") || strings.HasSuffix(r.URL.Path, "/ingress-assignment")) {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		committed := httptest.NewRecorder()
		next.ServeHTTP(committed, r)
		mu.Lock()
		bodies[r.URL.Path] = append(bodies[r.URL.Path], body)
		results[r.URL.Path] = append(results[r.URL.Path], bytes.Clone(committed.Body.Bytes()))
		attempt := len(bodies[r.URL.Path])
		mu.Unlock()
		if committed.Code != http.StatusCreated {
			t.Errorf("assignment status = %d", committed.Code)
		}
		if attempt <= 2 && committed.Code == http.StatusCreated {
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
	})
	leases := map[string]controlstate.IngressLeaseIdentity{}
	for index := range 2 {
		id := fmt.Sprintf("ingress-%d", index)
		lease, err := f.database.RegisterIngress(t.Context(), controlstate.IngressRegistration{IngressID: id, IngressRunID: connectorID(t, opaqueid.IngressRunPrefix), ProtocolVersion: 1,
			ConnectionCapacity: 1, ConnectorAddress: fmt.Sprintf("127.0.0.1:%d", 9441+index), ConnectorTLSServerName: "ingress.example.test"}, time.Now(), time.Minute)
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
	device, err := adapter.ConnectorSigner(t.Context(), f.identity)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := adapter.ConnectorAssignment(t.Context(), f.service.Id, device.Subject, 0); err == nil {
			t.Fatal("lost startup response succeeded")
		}
		if f.reservations(t) != 2 {
			t.Fatal("startup retry changed reserved capacity")
		}
	}
	healthy, err := adapter.ConnectorAssignment(t.Context(), f.service.Id, device.Subject, 0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := adapter.ConnectorAssignment(t.Context(), f.service.Id, device.Subject, 1)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := tunnelv1.NewConnectorSessionNonce()
	hello := tunnelv1.ConnectorSessionHello{ProtocolVersion: 1, Kind: "connector_session", ServiceID: f.service.Id,
		SessionID: healthy.SessionID, Credential: healthy.Credential, Subject: device.Subject, Nonce: nonce}
	digest, _ := hello.Claim().Digest()
	hello.Signature = device.Sign(digest)
	if _, err := f.database.AuthenticateVisitorConnector(t.Context(), leases[healthy.IngressID], hello.Claim(), netip.MustParseAddr("127.0.0.1"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.RenewIngress(t.Context(), controlstate.IngressRenewal{IngressLeaseIdentity: leases[healthy.IngressID], ReportedConnections: 1}, time.Now(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ReleaseConnectorAssignment(t.Context(), other.SessionID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := adapter.ConnectorAssignment(t.Context(), f.service.Id, device.Subject, 1); err == nil {
			t.Fatal("lost renewal response succeeded")
		}
		if f.reservations(t) != 2 {
			t.Fatal("renewal retry changed reserved capacity")
		}
	}
	renewed, err := adapter.ConnectorAssignment(t.Context(), f.service.Id, device.Subject, 1)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.IngressID == healthy.IngressID || renewed.SessionID == other.SessionID {
		t.Fatal("renewal did not preserve independent slots")
	}
	var total int
	var valid bool
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.connector_sessions`).Scan(&total); err != nil || total != 3 {
		t.Fatalf("lost responses created extra reservations: count=%d err=%v", total, err)
	}
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT revoked_at IS NULL AND bound_at IS NOT NULL FROM control.connector_sessions WHERE id=$1`, healthy.SessionID).Scan(&valid); err != nil || !valid {
		t.Fatal("renewal invalidated healthy sibling", err)
	}
	mu.Lock()
	defer mu.Unlock()
	keys := map[string]bool{}
	for path, requests := range bodies {
		if len(requests) != 3 {
			t.Fatalf("expected three attempts, got %d", len(requests))
		}
		var request struct {
			IdempotencyKey string `json:"idempotency_key"`
		}
		if err := json.Unmarshal(requests[0], &request); err != nil || request.IdempotencyKey == "" || keys[request.IdempotencyKey] {
			t.Fatal("missing or reused operation retry key")
		}
		keys[request.IdempotencyKey] = true
		for i := range requests {
			if !bytes.Equal(requests[0], requests[i]) || !bytes.Equal(results[path][0], results[path][i]) {
				t.Fatal("retry changed request, IDs, or credentials")
			}
		}
		// credentials must be recoverable only through the encrypted result.
		var setups []controlv1.ConnectorSessionSetup
		if strings.HasSuffix(path, "/ingress-assignments") {
			_ = json.Unmarshal(results[path][0], &setups)
		} else {
			var setup controlv1.ConnectorSessionSetup
			_ = json.Unmarshal(results[path][0], &setup)
			setups = append(setups, setup)
		}
		var ciphertext []byte
		if err := f.inspect.QueryRowContext(t.Context(), `SELECT result_ciphertext FROM control.connector_ingress_assignment_requests WHERE identity_id=$1 AND idempotency_key=$2`, f.identity, request.IdempotencyKey).Scan(&ciphertext); err != nil {
			t.Fatal(err)
		}
		for _, setup := range setups {
			if setup.SessionCredential == "" || bytes.Contains(ciphertext, []byte(setup.SessionCredential)) {
				t.Fatal("assignment result was not encrypted")
			}
		}
	}
}
