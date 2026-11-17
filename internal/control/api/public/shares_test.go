package public

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type shareStoreStub struct {
	created                            controlstate.CreateShareRequest
	share                              controlstate.Share
	guestID                            string
	guestURL                           string
	guestFailure                       error
	guestOwner, guestService, guestKey string
	guestCredential                    controlstate.GuestCredential
	guestFingerprint                   [32]byte
	guestCalls                         int
}

func (s *shareStoreStub) CreateShare(_ context.Context, request controlstate.CreateShareRequest, now time.Time) (controlstate.Share, error) {
	s.created = request
	scope := "service"
	if request.PreviewID != "" {
		scope = "preview"
	}
	team := request.TeamID
	if team == "" {
		team = "team_1"
	}
	s.share = controlstate.Share{
		ID: "shr_example", PreviewID: request.PreviewID, TeamID: team, Scope: scope, Label: request.Label,
		CreatedByIdentityID: request.ActingIdentityID, ServiceIDs: slices.Clone(request.ServiceIDs),
		EntryServiceID: request.EntryServiceID, EntryHostname: "web.example.test",
		CreatedAt: now, ExpiresAt: request.ExpiresAt,
	}
	return s.share, nil
}

func (s *shareStoreStub) CreateGuestShare(_ context.Context, credential controlstate.GuestCredential, serviceID, key, label string, fingerprint [32]byte, expiresAt, now time.Time) (controlstate.Share, error) {
	s.guestCalls++
	s.guestCredential, s.guestKey, s.guestFingerprint = credential, key, fingerprint
	if s.guestFailure != nil {
		return controlstate.Share{}, s.guestFailure
	}
	if credential.SourceIP != netip.MustParseAddr("192.0.2.7") {
		return controlstate.Share{}, authorization.ErrGuestIPChanged
	}
	if serviceID != s.guestService {
		return controlstate.Share{}, controlstate.ErrShareStale
	}
	s.guestID, s.guestURL = s.guestOwner, serviceID
	s.share = controlstate.Share{SchemaVersion: 1, ID: "shr_guest", Scope: "guest", Label: label, GuestID: s.guestOwner,
		ServiceIDs: []string{serviceID}, EntryServiceID: serviceID, EntryHostname: "web.example.test", CreatedAt: now, ExpiresAt: expiresAt}
	return s.share, nil
}

func (s *shareStoreStub) GetShare(_ context.Context, _ string) (controlstate.Share, error) {
	return s.share, nil
}

func (s *shareStoreStub) GetShareForManagement(_ context.Context, _, actor string, _ time.Time) (controlstate.Share, error) {
	if actor != s.share.CreatedByIdentityID {
		return controlstate.Share{}, controlstate.ErrShareNotFound
	}
	return s.share, nil
}

func (*shareStoreStub) ResolveCompanyAccount(context.Context, string, string) (string, error) {
	return "identity_1", nil
}

func (s *shareStoreStub) ListShares(_ context.Context, _, _ string) (controlstate.SharePage, error) {
	return controlstate.SharePage{Shares: []controlstate.Share{s.share}}, nil
}

func (s *shareStoreStub) ListTeamShares(_ context.Context, teamID, identityID, _ string) (controlstate.SharePage, error) {
	if teamID != s.share.TeamID || identityID != s.share.CreatedByIdentityID {
		return controlstate.SharePage{}, nil
	}
	return controlstate.SharePage{Shares: []controlstate.Share{s.share}}, nil
}

func (s *shareStoreStub) RevokeShare(_ context.Context, _, actor string, now time.Time) (controlstate.Share, error) {
	if actor != s.share.CreatedByIdentityID {
		return controlstate.Share{}, controlstate.ErrShareNotFound
	}
	s.share.RevokedAt = &now
	return s.share, nil
}

func TestShareCreateChecksIncludedServiceAndDeliversCredentialOnce(t *testing.T) {
	preview := &previewStoreStub{preview: controlstate.Preview{
		ID: "pv_preview", TeamID: "team_1", CreatedByIdentityID: "identity_1", ServiceIDs: []string{"svc_1"},
	}}
	authorizer := &recordingAuthorizer{principal: testControlReadPrincipal()}
	shares := &shareStoreStub{}
	h := &handler{previews: preview, shares: shares, authorizer: authorizer}
	create := func(ids string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/previews/pv_preview/shares", strings.NewReader(fmt.Sprintf(`{"service_ids":%s,"entry_service_id":"svc_1","expires_at":"%s"}`, ids, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339))))
		request.Header.Set("Authorization", "Bearer access-token")
		request.Header.Set("Idempotency-Key", "first-share")
		response := httptest.NewRecorder()
		h.CreateShare(response, request, "pv_preview", controlv1.CreateShareParams{})
		return response
	}
	if response := create(`["svc_other"]`); response.Code != http.StatusBadRequest || shares.created.PreviewID != "" {
		t.Fatalf("service outside preview = %d %s, stored=%+v", response.Code, response.Body.String(), shares.created)
	}
	response := create(`["svc_1"]`)
	if response.Code != http.StatusCreated || shares.created.PreviewID != "pv_preview" ||
		shares.created.ActingIdentityID != "identity_1" || !slices.Equal(shares.created.ServiceIDs, []string{"svc_1"}) || shares.created.EntryServiceID != "svc_1" ||
		strings.Contains(response.Body.String(), "fingerprint") || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("share creation = %d %s, request=%+v", response.Code, response.Body.String(), shares.created)
	}
	var creation controlv1.ShareCreation
	if err := json.Unmarshal(response.Body.Bytes(), &creation); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(creation.TokenSource.Secret)
	if err != nil || len(raw) != 32 || sha256.Sum256(raw) != shares.created.SecretFingerprint || creation.TokenSource.ShareId != shares.share.ID || creation.Link != "https://web.example.test/__tnl/share/"+shares.share.ID+"."+creation.TokenSource.Secret {
		t.Fatal("creation did not deliver a complete credential for the saved digest")
	}
	read := httptest.NewRequest(http.MethodGet, "/v1/shares/shr_example", nil)
	read.Header.Set("Authorization", "Bearer access-token")
	list := httptest.NewRecorder()
	h.ListShares(list, read, "pv_preview", controlv1.ListSharesParams{})
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"id":"shr_example"`) || strings.Contains(list.Body.String(), creation.TokenSource.Secret) || strings.Contains(list.Body.String(), "token_source") {
		t.Fatalf("share list = %d %s", list.Code, list.Body.String())
	}
	teamRequest := httptest.NewRequest(http.MethodGet, "/v1/shares?team_id=team_1", nil)
	teamRequest.Header.Set("Authorization", "Bearer access-token")
	teamList := httptest.NewRecorder()
	h.ListTeamShares(teamList, teamRequest, controlv1.ListTeamSharesParams{})
	if teamList.Code != http.StatusOK || !strings.Contains(teamList.Body.String(), `"id":"shr_example"`) {
		t.Fatalf("team share list = %d %s", teamList.Code, teamList.Body.String())
	}
	otherRequest := httptest.NewRequest(http.MethodGet, "/v1/shares?team_id=team_other", nil)
	otherRequest.Header.Set("Authorization", "Bearer access-token")
	otherList := httptest.NewRecorder()
	h.ListTeamShares(otherList, otherRequest, controlv1.ListTeamSharesParams{})
	if otherList.Code != http.StatusNotFound {
		t.Fatalf("other team shares were listed: %d %s", otherList.Code, otherList.Body.String())
	}
	authorizer.principal.identityID = "different-identity"
	denied := httptest.NewRecorder()
	h.RevokeShare(denied, read, "shr_example")
	if denied.Code != http.StatusNotFound || shares.share.RevokedAt != nil {
		t.Fatalf("other identity revoked a share: %d %s", denied.Code, denied.Body.String())
	}
	authorizer.principal.identityID = "identity_1"
	revoked := httptest.NewRecorder()
	h.RevokeShare(revoked, read, "shr_example")
	if revoked.Code != http.StatusOK || shares.share.RevokedAt == nil ||
		!strings.Contains(revoked.Body.String(), `"revoked_at"`) || strings.Contains(revoked.Body.String(), "fingerprint") {
		t.Fatalf("revoke = %d %s", revoked.Code, revoked.Body.String())
	}
}

func TestDirectShareCreationAuthorizesOneServiceWithoutPreview(t *testing.T) {
	shares := &shareStoreStub{}
	authorizer := &recordingAuthorizer{principal: testControlReadPrincipal()}
	h := &handler{shares: shares, authorizer: authorizer}
	body := fmt.Sprintf(`{"service_ids":["svc_1"],"entry_service_id":"svc_1","expires_at":"%s","label":"ci"}`,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	request := httptest.NewRequest(http.MethodPost, "/v1/shares", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Idempotency-Key", "exact-url")
	response := httptest.NewRecorder()
	h.CreateServiceShare(response, request, controlv1.CreateServiceShareParams{})
	if response.Code != http.StatusCreated || shares.created.PreviewID != "" || shares.created.Label != "ci" ||
		len(shares.created.ServiceIDs) != 1 || shares.created.ServiceIDs[0] != "svc_1" || shares.created.EntryServiceID != "svc_1" ||
		!strings.Contains(response.Body.String(), `"scope":"service"`) || strings.Contains(response.Body.String(), `"preview_id"`) {
		t.Fatalf("exact share = %d %s, request=%+v", response.Code, response.Body.String(), shares.created)
	}
	read := httptest.NewRequest(http.MethodGet, "/v1/shares/shr_example", nil)
	read.Header.Set("Authorization", "Bearer access-token")
	result := httptest.NewRecorder()
	h.GetShare(result, read, "shr_example")
	if result.Code != http.StatusOK {
		t.Fatalf("read exact share = %d %s", result.Code, result.Body.String())
	}
}

func TestGuestShareChecksTrialCredentialAndSourceBeforeMinting(t *testing.T) {
	guest := guestAPIStore(t)
	shares := &shareStoreStub{guestOwner: guest.guest.ID, guestService: guest.record.ID}
	fallback := &guestHumanAuthorizer{}
	h := &handler{guests: guest, shares: shares, authorizer: fallback}
	body := fmt.Sprintf(`{"service_ids":[%q],"entry_service_id":%q,"expires_at":"%s","label":"trial"}`,
		guest.record.ID, guest.record.ID, guest.guest.ExpiresAt.UTC().Format(time.RFC3339Nano))
	for _, test := range []struct {
		ip     string
		status int
	}{
		{"192.0.2.8:1234", http.StatusForbidden},
		{"192.0.2.7:1234", http.StatusCreated},
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/shares", strings.NewReader(body))
		request.RemoteAddr = test.ip
		request.Header.Set("Authorization", "Bearer guest-token")
		request.Header.Set("Idempotency-Key", "guest-share")
		request.Header.Set("X-Forwarded-For", "192.0.2.7")
		response := httptest.NewRecorder()
		h.CreateServiceShare(response, request, controlv1.CreateServiceShareParams{})
		if response.Code != test.status {
			t.Fatalf("guest share from %s = %d", test.ip, response.Code)
		}
		if test.status == http.StatusForbidden && shares.guestID != "" ||
			test.status == http.StatusCreated && (shares.guestID != guest.guest.ID || shares.guestURL != guest.record.ID || shares.share.Label != "trial") || fallback.reads != 0 {
			t.Fatal("guest share leaked or bypassed state source check", response.Code)
		}
		if test.status == http.StatusCreated {
			var result controlv1.ShareCreation
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			secret, err := base64.RawURLEncoding.DecodeString(result.TokenSource.Secret)
			if err != nil || sha256.Sum256(secret) != shares.guestFingerprint ||
				result.Share.GuestId != guest.guest.ID || result.Share.TeamId != "" || result.Share.CreatedByIdentityId != "" ||
				strings.Contains(response.Body.String(), `"team_id"`) || strings.Contains(response.Body.String(), `"created_by_identity_id"`) {
				t.Fatal("guest share fabricated a human owner or changed its credential")
			}
		}
	}
	rejected := func(id string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/shares", strings.NewReader(strings.ReplaceAll(body, guest.record.ID, id)))
		request.RemoteAddr = "192.0.2.7:1234"
		request.Header.Set("Authorization", "Bearer guest-token")
		request.Header.Set("Idempotency-Key", id)
		response := httptest.NewRecorder()
		h.CreateServiceShare(response, request, controlv1.CreateServiceShareParams{})
		return response
	}
	unrelated, missing := rejected("svc_unrelated"), rejected("svc_missing")
	if unrelated.Code != http.StatusConflict || missing.Code != unrelated.Code {
		t.Fatal("guest share responses revealed whether an unowned service exists")
	}
	guest.lookupErr = errors.New("guest database unavailable")
	request := httptest.NewRequest(http.MethodPost, "/v1/shares", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer guest-token")
	request.Header.Set("Idempotency-Key", "failed-lookup")
	response := httptest.NewRecorder()
	h.CreateServiceShare(response, request, controlv1.CreateServiceShareParams{})
	if response.Code != http.StatusServiceUnavailable || fallback.reads != 0 {
		t.Fatalf("guest lookup error fell through to team authorization: %d %s", response.Code, response.Body.String())
	}
}

func TestGuestTrialCannotShareAnArbitraryPreviewOrMismatchedBody(t *testing.T) {
	for _, tc := range []struct {
		name, preview, ids, entry string
		status                    int
	}{
		{"preview", "pv_arbitrary", `["svc_guest"]`, "svc_guest", 403},
		{"entry", "", `["svc_guest"]`, "svc_other", 400},
		{"multiple", "", `["svc_guest","svc_other"]`, "svc_guest", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trials := guestAPIStore(t)
			shares, human := &shareStoreStub{}, &guestHumanAuthorizer{}
			h := &handler{guests: trials, shares: shares, authorizer: human}
			body := fmt.Sprintf(`{"service_ids":%s,"entry_service_id":%q,"expires_at":%q}`, tc.ids, tc.entry,
				trials.guest.ExpiresAt.Format(time.RFC3339Nano))
			r := httptest.NewRequest(http.MethodPost, "/v1/shares", strings.NewReader(body))
			r.RemoteAddr = "192.0.2.7:1234"
			r.Header.Set("Authorization", "Bearer guest-token")
			r.Header.Set("Idempotency-Key", "share")
			w := httptest.NewRecorder()
			h.createShare(w, r, tc.preview)
			if w.Code != tc.status || human.reads != 0 || shares.guestCalls != 0 || shares.created.ActingIdentityID != "" {
				t.Fatal("trial reached generic preview or mismatched share management", w.Code)
			}
		})
	}
}

func TestUnrecognizedGuestCredentialUsesSignedInShareAuthorization(t *testing.T) {
	shares := &shareStoreStub{}
	authorizer := &guestHumanAuthorizer{}
	h := &handler{config: Config{GuestDemoEnabled: true}, guests: &guestCreationStoreStub{},
		shares: shares, authorizer: authorizer}
	body := fmt.Sprintf(`{"service_ids":["svc_1"],"entry_service_id":"svc_1","expires_at":"%s"}`,
		time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
	request := httptest.NewRequest(http.MethodPost, "/v1/shares", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer human-token")
	request.Header.Set("Idempotency-Key", "signed-in-share")
	response := httptest.NewRecorder()
	h.CreateServiceShare(response, request, controlv1.CreateServiceShareParams{})
	if response.Code != http.StatusCreated || shares.created.ActingIdentityID != "identity_1" ||
		authorizer.reads != 1 || !slices.Equal(shares.created.ServiceIDs, []string{"svc_1"}) {
		t.Fatalf("signed-in share = %d %s", response.Code, response.Body.String())
	}
}

func TestGuestShareMissingServiceOwnershipFailsClosed(t *testing.T) {
	shares := &shareStoreStub{guestFailure: errors.New("guest ownership unavailable")}
	guest := guestAPIStore(t)
	fallback := &guestHumanAuthorizer{}
	h := &handler{config: Config{GuestDemoEnabled: true}, guests: guest, shares: shares,
		authorizer: fallback}
	body := fmt.Sprintf(`{"service_ids":["svc_guest"],"entry_service_id":"svc_guest","expires_at":"%s"}`, guest.guest.ExpiresAt.UTC().Format(time.RFC3339Nano))
	request := httptest.NewRequest(http.MethodPost, "/v1/shares", strings.NewReader(body))
	request.RemoteAddr = "192.0.2.7:1234"
	request.Header.Set("Authorization", "Bearer guest-token")
	request.Header.Set("Idempotency-Key", "missing-guest-service")
	response := httptest.NewRecorder()
	h.CreateServiceShare(response, request, controlv1.CreateServiceShareParams{})
	if response.Code != http.StatusServiceUnavailable ||
		shares.share.ID != "" || fallback.reads != 0 {
		t.Fatal("missing guest ownership fabricated authority or hid its dependency", response.Code, response.Body.String())
	}
}
