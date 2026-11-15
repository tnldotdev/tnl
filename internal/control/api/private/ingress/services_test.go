package ingress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/testutil/ipdigest"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestReadIngressServicesHTTPAndDirectReturnTheSameSnapshot(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	identity := controlstate.IngressLeaseIdentity{IngressID: "ingress-one", IngressRunID: "ir_" + strings.Repeat("a", 22), IngressLeaseRevision: 3}
	body := ingressv1.IngressLeaseIdentity{IngressId: identity.IngressID, IngressRunId: identity.IngressRunID, IngressLeaseRevision: 3}
	current := controlstate.IngressServices{
		ObservedAt: now, ValidUntil: now.Add(10 * time.Second),
		Runs: []controlstate.IngressServiceRun{{
			ServiceID: "svc_" + strings.Repeat("a", 22), RunID: "srun_" + strings.Repeat("a", 22), RunNumber: 4,
			Protocol: "http", Hostname: "app.example", Port: 443, EndpointRevision: 2, ValidUntil: now.Add(8 * time.Second),
			Anonymous: true, IP: &controlv1.VisitorPolicyIP{Key: []byte{1, 2}, Prefixes: []controlv1.HashedIPPrefix{}},
			TemporaryBlocks:   []httpprotection.TemporaryBlock{{SourceDigest: ipdigest.Hash("192.0.2.4"), ExpiresAt: now.Add(time.Minute)}},
			TemporaryBlockKey: ipdigest.Key(),
			Traffic:           trafficlimits.Limits{Connections: 12, TotalConnections: 23, UploadBytes: 1024, DownloadBytes: 2048, TotalUploadBytes: 4096, TotalDownloadBytes: 8192},
			Relays: []controlstate.ServiceRelay{{
				PublisherConnectionID: "pc_" + strings.Repeat("a", 22), ConnectionSlot: 1, ConnectionAssignmentRevision: 5,
				RelayServiceID: "relay-service", RelayID: "relay-process", RelayRunID: "rr_" + strings.Repeat("a", 22),
				RelayLeaseRevision: 6, LeaseExpiresAt: now.Add(30 * time.Second), ServingUntil: now.Add(time.Minute), InternalRelayAddress: "relay.internal:443", TLSServerName: "relay.example",
			}},
			SourceAuthority: []byte("source evidence"), SourceKey: []byte("source key"),
		}},
	}
	calls := 0
	store := &ingressStoreStub{readIngressServices: func(_ context.Context, got controlstate.IngressLeaseIdentity, at time.Time) (controlstate.IngressServices, error) {
		calls++
		if got != identity || !at.Equal(now) {
			t.Fatal("routing read changed its ingress identity or observation time")
		}
		return current, nil
	}}
	direct, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	want, err := direct.ReadIngressServices(t.Context(), identity.IngressID, body)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(testIngressHandler(t, store, now, nil))
	defer server.Close()
	client, err := ingressv1.NewClientWithResponses(server.URL, ingressv1.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
		request.Header.Set("Authorization", "Bearer "+testIngressClusterSecret)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.ReadIngressServicesWithResponse(t.Context(), identity.IngressID, body)
	if err != nil || response == nil || response.JSON200 == nil {
		t.Fatal("routing snapshot HTTP read failed", err, response)
	}
	if !reflect.DeepEqual(*response.JSON200, want) || calls != 2 {
		t.Fatal("HTTP and standalone routing reads returned different facts")
	}
	run := want.Runs[0]
	if run.ServiceId != current.Runs[0].ServiceID || run.ServiceRunId != current.Runs[0].RunID ||
		run.EndpointRevision != 2 || run.Traffic.Connections != 12 || *run.Traffic.TotalConnections != 23 ||
		*run.Traffic.TotalUploadBytes != 4096 || *run.Traffic.TotalDownloadBytes != 8192 ||
		!reflect.DeepEqual(run.ConnectedRelays, privateRelayResponses(current.Runs[0].Relays)) ||
		!reflect.DeepEqual(run.TemporaryBlocks, current.Runs[0].TemporaryBlocks) ||
		!reflect.DeepEqual(run.TemporaryBlockKey, current.Runs[0].TemporaryBlockKey) ||
		!reflect.DeepEqual(run.SourceKey, current.Runs[0].SourceKey) || !reflect.DeepEqual(run.SourceAuthority, current.Runs[0].SourceAuthority) {
		t.Fatal("routing response omitted endpoint, capacity, relay, or source facts")
	}
	relay := run.ConnectedRelays[0]
	if !relay.LeaseExpiresAt.Equal(now.Add(30*time.Second)) || !relay.ServingUntil.Equal(now.Add(time.Minute)) {
		t.Fatal("routing response mixed availability with serving authority", relay)
	}
}

func TestReadIngressServicesChecksAuthenticationAndExactLease(t *testing.T) {
	now := time.Now()
	calls := 0
	store := &ingressStoreStub{readIngressServices: func(context.Context, controlstate.IngressLeaseIdentity, time.Time) (controlstate.IngressServices, error) {
		calls++
		return controlstate.IngressServices{}, controlstate.ErrIngressLeaseStale
	}}
	handler := testIngressHandler(t, store, now, nil)
	path := "/internal/v1/ingresses/ingress-one/services"
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || calls != 0 {
		t.Fatal("unauthenticated routing read reached state", response.Code, calls)
	}
	for _, test := range []struct {
		name string
		body string
		code int
	}{
		{"path mismatch", `{"ingress_id":"ingress-two","ingress_run_id":"ir_aaaaaaaaaaaaaaaaaaaaaa","ingress_lease_revision":1}`, http.StatusBadRequest},
		{"missing revision", `{"ingress_id":"ingress-one","ingress_run_id":"ir_aaaaaaaaaaaaaaaaaaaaaa"}`, http.StatusBadRequest},
		{"unknown field", `{"ingress_id":"ingress-one","ingress_run_id":"ir_aaaaaaaaaaaaaaaaaaaaaa","ingress_lease_revision":1,"visitor_id":"not-used"}`, http.StatusBadRequest},
		{"stale lease", `{"ingress_id":"ingress-one","ingress_run_id":"ir_aaaaaaaaaaaaaaaaaaaaaa","ingress_lease_revision":1}`, http.StatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := authenticatedIngressRequest(http.MethodPost, path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.code {
				t.Fatal("routing returned the wrong lease error", response.Code, response.Body.String())
			}
		})
	}
	if calls != 1 {
		t.Fatal("an invalid routing request reached state", calls)
	}
}
