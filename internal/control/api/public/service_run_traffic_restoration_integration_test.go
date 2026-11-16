package public

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type restoredTrafficRequest struct {
	service, key string
	publisher    controlstate.PublisherIdentity
	request      controlstate.ServiceRunRequest
}

type restoredTrafficStore struct {
	ServiceRunStore
	mu       sync.Mutex
	requests []restoredTrafficRequest
}

func (s *restoredTrafficStore) PrepareServiceRun(ctx context.Context, service string, publisher controlstate.PublisherIdentity, key string, now time.Time, request controlstate.ServiceRunRequest) (controlstate.ServiceRunPreparation, error) {
	s.mu.Lock()
	s.requests = append(s.requests, restoredTrafficRequest{service, key, publisher, request})
	s.mu.Unlock()
	return s.ServiceRunStore.PrepareServiceRun(ctx, service, publisher, key, now, request)
}

func (s *restoredTrafficStore) snapshot() []restoredTrafficRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

func TestIntegrationServiceRunRestoredTrafficRegionsAuthorityAndProjection(t *testing.T) {
	f, session, _, team, service := serviceFixture(t)
	ctx := t.Context()
	defaults, ceiling := trafficlimits.Default(), trafficlimits.Ceiling()
	defaults.UploadBytes = 4 << 20
	recorder := &restoredTrafficStore{ServiceRunStore: f.d}
	stores := DatabaseStores(f.d)
	stores.ServiceRuns = recorder
	h, err := NewHandler(Config{TrafficDefaults: defaults, TrafficCeiling: ceiling}, stores, f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	q := controlstatedb.New(f.sql)
	actor, err := q.GetTeamActorContext(ctx, controlstatedb.GetTeamActorContextParams{TeamID: team.ID, IdentityID: session.Identity.Identity.Id})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := f.d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{
		Scope: controlstate.PublisherScope{TeamID: team.ID, Kind: "service", ServiceID: service.ID}, Protocols: []string{"http"},
		Name: "restored-traffic", Kind: "installed", EditorID: session.Identity.Identity.Id,
		EditorMembershipID: actor.ActorMembershipID, PolicyRevision: uint64(actor.PolicyRevision), Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := f.d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	audience := server.URL + "/v1/publisher-token"
	proof, err := publisherproof.Sign(publisher.ID, publisher.KeyID, publisher.GrantID, audience, private, f.now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := f.d.ExchangePublisherAssertion(ctx, publisher.ID, publisher.GrantID, audience, proof, "127.0.0.1", f.now)
	if err != nil {
		t.Fatal(err)
	}
	call := func(id, token, key, suffix string, want int, code string) controlv1.ServiceRunPreparation {
		t.Helper()
		body := fmt.Sprintf(`{"protocol":"http","trust_revision":%q%s}`, fmt.Sprint(service.TrustRevision), suffix)
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/services/"+id+"/runs", bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		wire, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want {
			t.Fatalf("run HTTP status=%d want=%d: %v %s", response.StatusCode, want, err, wire)
		}
		if want != 201 {
			var problem controlv1.Problem
			if json.Unmarshal(wire, &problem) != nil || string(problem.Code) != code {
				t.Fatalf("run problem code=%s want=%s", problem.Code, code)
			}
			return controlv1.ServiceRunPreparation{}
		}
		var prepared controlv1.ServiceRunPreparation
		if err := json.Unmarshal(wire, &prepared); err != nil {
			t.Fatal(err)
		}
		return prepared
	}
	call(service.ID, "", "missing-denial", "", 401, "unauthenticated")
	call(service.ID, session.AccessToken, "human-denial", "", 401, "unauthenticated")
	if len(recorder.snapshot()) != 0 {
		t.Fatal("missing bearer or control session reached publisher preparation")
	}
	for index, regions := range []string{`["sjc"]`, `["aws:sjc"]`, `["fly:us-west-1"]`, `["FLY:SJC","fly:sjc"]`} {
		call(service.ID, access.Token, fmt.Sprintf("invalid-regions-%d", index), `,"preferred_regions":`+regions, 400, "invalid_request")
	}
	call(service.ID, access.Token, "ceiling-denial", fmt.Sprintf(`,"traffic":{"connections":%d}`, ceiling.Connections+1), 400, "traffic_selection_invalid")
	defaultPreparation := call(service.ID, access.Token, "default-traffic", "", 201, "")
	if defaultPreparation.Traffic.Connections != defaults.Connections {
		t.Fatal("omitted traffic did not use configured defaults")
	}
	if err := f.d.CloseServiceRun(ctx, service.ID, defaultPreparation.ServiceRunId, defaultPreparation.RunToken, time.Now()); err != nil {
		t.Fatal(err)
	}
	suffix := `,"preferred_regions":["FLY:SJC","aws:us-west-1"],"traffic":{"connections":48,"rate_per":"2s","total_upload_bytes":1048576}`
	prepared := call(service.ID, access.Token, "explicit-traffic", suffix, 201, "")
	requests := recorder.snapshot()
	last := requests[len(requests)-1]
	selected := last.request.TrafficSelection
	if last.service != service.ID || last.key != "explicit-traffic" || last.publisher.ID != publisher.ID ||
		last.publisher.GrantID != publisher.GrantID || last.publisher.KeyID != publisher.KeyID ||
		last.request.Metadata.Protocol != "http" || last.request.Metadata.TrustRevision != service.TrustRevision ||
		!slices.Equal(last.request.PreferredRegions, []string{"FLY:SJC", "aws:us-west-1"}) ||
		selected == nil || selected.Connections == nil || *selected.Connections != 48 ||
		selected.RatePer == nil || *selected.RatePer != "2s" ||
		selected.TotalUploadBytes == nil || *selected.TotalUploadBytes != 1048576 ||
		last.request.TrafficDefaults != defaults || last.request.TrafficCeiling != ceiling {
		t.Fatal("HTTP forwarding lost exact current publisher authority, preferences, or traffic intent")
	}
	stored, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: prepared.ServiceRunId, ServiceID: service.ID})
	if err != nil {
		t.Fatal(err)
	}
	expiry := stored.PreparationExpiresAt.Time
	if stored.PublisherExpiresAt.Time.Before(expiry) {
		expiry = stored.PublisherExpiresAt.Time
	}
	if !slices.Equal(stored.PreferredRegions, []string{"fly:sjc", "aws:us-west-1"}) ||
		prepared.ServiceId != service.ID || prepared.TeamId != team.ID || prepared.ServiceRunId != stored.ID ||
		prepared.RunNumber != stored.RunNumber || prepared.IdempotencyKey != "explicit-traffic" ||
		prepared.PublisherIdentityId != publisher.ID || prepared.PublisherGrantId != publisher.GrantID ||
		prepared.PublisherKeyId != publisher.KeyID || !prepared.ExpiresAt.Equal(expiry) ||
		prepared.Hostname != stored.CertificateHostname || prepared.DomainId != stored.CertificateDomainID.String ||
		prepared.RequirePostQuantum != stored.RequirePostQuantum || prepared.CertificatePlan == nil ||
		prepared.CertificatePlan.CacheKey != stored.CertificateCacheKey || prepared.CertificatePlan.Scope != stored.CertificateScope ||
		!slices.Equal(prepared.CertificatePlan.Identifiers, stored.CertificateIdentifiers) ||
		prepared.Traffic.Connections != 48 || prepared.Traffic.RatePerNs != int64(2*time.Second) ||
		prepared.Traffic.TotalUploadBytes == nil || *prepared.Traffic.TotalUploadBytes != 1048576 {
		t.Fatal("authoritative preparation response or stored canonical preferences changed")
	}
	retry := call(service.ID, access.Token, "explicit-traffic", suffix, 201, "")
	if !reflect.DeepEqual(retry, prepared) {
		t.Fatal("same traffic intent changed the authoritative preparation")
	}
	other, err := f.d.CreateServiceAt(ctx, team.ID, session.Identity.Identity.Id, "out-of-scope", "out-of-scope", controlstate.ServicePlacement{}, f.now,
		controlstate.ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	call(other.ID, access.Token, "foreign-service", "", 404, "not_found")
	var foreignRuns int
	if err := f.sql.QueryRow(ctx, `SELECT count(*) FROM control.service_runs WHERE service_id=$1`, other.ID).Scan(&foreignRuns); err != nil || foreignRuns != 0 {
		t.Fatal("out-of-scope publisher created durable run state", err)
	}
	if err := f.d.RevokePublisherGrant(ctx, team.ID, publisher.ID, publisher.GrantID, session.Identity.Identity.Id, time.Now()); err != nil {
		t.Fatal(err)
	}
	beforeRevoked := len(recorder.snapshot())
	call(service.ID, access.Token, "revoked-prepare", "", 401, "unauthenticated")
	if len(recorder.snapshot()) != beforeRevoked {
		t.Fatal("revoked publisher reached run preparation")
	}
}
