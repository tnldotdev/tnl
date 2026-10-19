package controlapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestPublishRunTrafficInputBoundary(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{}`, 0}, {`{"traffic":{"connections":48,"rate":40,"rate_per":"2s","upload_bytes":4194304}}`, 0},
		{`{"traffic":{"connections":0}}`, 400}, {`{"traffic":{"rate_per":"1ns"}}`, 400},
		{`{"traffic":{"upload_bytes":1}}`, 400}, {`{"traffic":{"unknown":1}}`, 400}, {`{"unknown":1}`, 400},
		{`{} {}`, 400}, {`null`, 400}, {`{"traffic":null}`, 400},
	} {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
		w := httptest.NewRecorder()
		selection, ok := publishRunTrafficSelection(w, r)
		if ok != (tc.status == 0) || !ok && w.Code != tc.status {
			t.Fatalf("body %s: %+v %t %d", tc.body, selection, ok, w.Code)
		}
	}
	w := httptest.NewRecorder()
	writeControlStateProblem(w, "select traffic", controlstate.ErrTrafficSelection)
	var problem controlv1.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil || problem.Code != controlv1.TrafficSelectionInvalid || w.Code != 400 {
		t.Fatalf("traffic problem: %+v %v", problem, err)
	}
}

func TestCreatePublishRunCarriesTrafficSeparatelyFromPublisherAuthority(t *testing.T) {
	store := &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: "url", TeamID: "team", DomainID: "domain", MembershipID: "member", PolicyRevision: 1,
		CanonicalHostname: "app.example.test", PublicURLScope: controlstate.PublicURLScopeMember,
		Target: "http://127.0.0.1:3000", MutationRevision: 1, AuthorizationPublishRunNumber: 1,
	}}
	store.publisher = &controlstate.PublisherIdentity{ID: "publisher", GrantID: "grant", KeyID: "key", CreatorID: "identity", Scope: controlstate.PublisherScope{TeamID: "team", Kind: "saved_url", PublicURLID: "url"}}
	store.publisherPlan = &authorization.CertificatePlan{CacheKey: "app.example.test", Scope: "app.example.test", Identifiers: []string{"app.example.test"}, ChallengeMethod: certificateidentity.ChallengeDNS01}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"traffic":{"connections":48,"rate_per":"2s","total_upload_bytes":1048576}}`))
	r.Header.Set("Authorization", "Bearer publisher-access")
	r.Header.Set("Idempotency-Key", "retry")
	r.Header.Set("Publisher-Run-Proof", "proof")
	w := httptest.NewRecorder()
	defaults, ceiling := trafficlimits.Default(), trafficlimits.Ceiling()
	(&handler{store: store, config: Config{TrafficDefaults: defaults, TrafficCeiling: ceiling, DNSAutomation: true}}).CreatePublishRun(w, r, "url", controlv1.CreatePublishRunParams{})
	if w.Code != http.StatusCreated {
		t.Fatalf("create run: %d %s", w.Code, w.Body.String())
	}
	request := store.sessionRequest
	if request.TrafficSelection == nil || *request.TrafficSelection.Connections != 48 || *request.TrafficSelection.RatePer != "2s" || *request.TrafficSelection.TotalUploadBytes != 1048576 || request.TrafficDefaults != defaults || request.TrafficCeiling != ceiling || request.PublisherIdentityID != "publisher" || request.PublisherRunProof != "proof" || len(request.RetrySecret) != 0 {
		t.Fatal("traffic hooks changed or lost publisher authorization")
	}
}

func TestPublishRunTrafficResponseUsesResolvedPeriod(t *testing.T) {
	l := trafficlimits.Default()
	l.RatePer = 2_000_000_000
	l.TotalConnections = 10
	r := trafficLimitsResponse(l)
	if r == nil || r.RatePerNs != 2_000_000_000 || r.TotalConnections == nil || *r.TotalConnections != 10 || r.TotalUploadBytes != nil {
		t.Fatalf("traffic wire limits: %+v", r)
	}
}
