package authority

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
)

func TestIntegrationDomainReleaseObservationHTTP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx, now := t.Context(), time.Now().UTC()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "domain_release_http")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	session, err := controltest.Session(ctx, d, "apps.example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	created, err := d.CreateTeam(ctx, controlstate.CreateTeamRequest{IdentityID: session.Identity.Identity.ID,
		DisplayName: "release-http", MemberSlug: "owner", IdempotencyKey: "release-team",
		RequestDigest: sha256.Sum256([]byte("release-team"))}, now)
	if err != nil {
		t.Fatal(err)
	}
	team := created.ID
	domain, err := d.ClaimTeamDomain(ctx, controlstate.ClaimDomainRequest{IdentityID: session.Identity.Identity.ID,
		TeamID: team, Domain: "release-http.example.test", IdempotencyKey: "release-http",
		RequestDigest: sha256.Sum256([]byte("release-http"))}, now)
	if err != nil {
		t.Fatal(err)
	}
	handler := testHandler(t, Config{}, d)
	path := "/v1/teams/" + team + "/domains/" + domain.ID
	request := func(method, path, token string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := request(http.MethodDelete, path, session.AccessToken.String()); w.Code != http.StatusNoContent {
		t.Fatalf("release acknowledgement = %d: %s", w.Code, w.Body)
	}
	w := request(http.MethodGet, path, session.AccessToken.String())
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("domain release has no authorized exact observation: %d %s", w.Code, w.Body)
	}
	var response struct {
		State   string `json:"state"`
		Release *struct {
			CompletionUnknown bool       `json:"completion_unknown"`
			Blockers          []string   `json:"blockers"`
			ReleasedAt        *time.Time `json:"released_at"`
		} `json:"release"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.State != "releasing" || response.Release == nil || !response.Release.CompletionUnknown ||
		!slices.Contains(response.Release.Blockers, "dns_authority") || response.Release.ReleasedAt != nil {
		t.Fatalf("release acknowledgement became a completion promise: %s", w.Body)
	}
	reader, err := d.CreateOIDCControlSession(ctx, "apps.example.test", controlstate.OIDCIdentity{Issuer: "https://identity.fixture.test",
		Subject: "domain-reader", DisplayName: "domain reader", AssertionDigest: sha256.Sum256([]byte("domain-reader")),
		AssertionExpiry: now.Add(time.Hour)}, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	foreign := "/v1/teams/" + reader.Identity.PersonalTeamID + "/domains/" + domain.ID
	if denied := request(http.MethodGet, foreign, reader.AccessToken.String()); denied.Code != http.StatusNotFound ||
		strings.Contains(denied.Body.String(), domain.CanonicalDomain) || strings.Contains(denied.Body.String(), "release\"") {
		t.Fatalf("foreign-team read disclosed domain facts: %d %s", denied.Code, denied.Body)
	}
	invitation, err := d.CreateTeamInvitation(ctx, controlstate.CreateInvitationRequest{IdentityID: session.Identity.Identity.ID,
		TeamID: team, MemberSlug: "reader", InitialRole: controlstate.TeamRoleMember, ExpiresAt: now.Add(time.Hour),
		IdempotencyKey: "reader", RequestDigest: sha256.Sum256([]byte("reader")), RetrySecret: []byte(strings.Repeat("r", 32))}, now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := d.AcceptInvitation(ctx, reader.Identity.Identity.ID, credentials.InvitationToken(invitation.Secret), now)
	if err != nil {
		t.Fatal(err)
	}
	if current := request(http.MethodGet, path, reader.AccessToken.String()); current.Code != http.StatusOK {
		t.Fatalf("current member lost team release visibility: %d %s", current.Code, current.Body)
	}
	if err := d.RemoveMembership(ctx, session.Identity.Identity.ID, team, member.ID, now); err != nil {
		t.Fatal(err)
	}
	if denied := request(http.MethodGet, path, reader.AccessToken.String()); denied.Code != http.StatusForbidden ||
		strings.Contains(denied.Body.String(), domain.CanonicalDomain) || strings.Contains(denied.Body.String(), "release\"") {
		t.Fatalf("removed member retained release facts: %d %s", denied.Code, denied.Body)
	}
	if denied := request(http.MethodGet, path, ""); denied.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous release read = %d", denied.Code)
	}
	ready, err := d.DNSAuthorityReleaseReady(ctx, domain.ID, now)
	if err != nil || !ready {
		t.Fatal("release preconditions did not settle", ready, err)
	}
	// preconditions alone do not complete release; only the final owner receipt
	// changes the public state. no external DNS provider execution is claimed.
	releasedAt := time.Now().UTC()
	work, found, err := d.ClaimDNSAuthorityWork(ctx, "release-observation", releasedAt, time.Minute)
	if err != nil || !found || work.Reference != domain.DNSAuthorityReference {
		t.Fatal("claim final DNS release work", found, err)
	}
	work.State, work.AvailableAt = controlstate.DNSAuthorityReleased, releasedAt
	if _, err := d.SaveDNSAuthorityWork(ctx, work, releasedAt); err != nil {
		t.Fatal(err)
	}
	w = request(http.MethodGet, path, session.AccessToken.String())
	response.Release = nil
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK ||
		response.State != "released" || response.Release == nil || response.Release.CompletionUnknown ||
		response.Release.ReleasedAt == nil || len(response.Release.Blockers) != 0 {
		t.Fatalf("final owner release not observed: %d %s %v", w.Code, w.Body, err)
	}
	list := request(http.MethodGet, "/v1/teams/"+team+"/domains", session.AccessToken.String())
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), domain.ID) {
		t.Fatalf("released history became a usable team domain: %d %s", list.Code, list.Body)
	}
}
