package public

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationShareCreationDoesNotStorePartiallyAuthorizedSnapshot(t *testing.T) {
	f, owner, secondOwner, team, _ := serviceFixture(t)
	ctx := t.Context()
	ownerID := owner.Identity.Identity.Id
	shared := serviceActorNamedService(t, f, team.ID, ownerID)
	invitation, err := f.d.CreateTeamInvitation(ctx, controlstate.CreateInvitationRequest{
		IdentityID: ownerID, TeamID: team.ID, MemberSlug: "second-owner", InitialRole: controlstate.TeamRoleOwner,
		IdempotencyKey: "second-owner", ExpiresAt: f.now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{7}, 32),
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.AcceptInvitation(ctx, secondOwner.Identity.Identity.Id, credentials.InvitationToken(invitation.Secret), f.now); err != nil {
		t.Fatal(err)
	}
	ownerCtx := controlstate.WithControlPrincipal(ctx, f.principal(owner))
	local, err := f.d.RealizeLocalProjectService(ownerCtx, controlstate.RealizeLocalProjectServiceRequest{
		TeamID: team.ID, ActorID: ownerID, ProjectKey: "share", SourceFingerprint: strings.Repeat("a", 64),
		Service: "web", WorktreeKey: "checkout", Configuration: controlstate.ProjectServiceConfiguration{Target: "localhost:3000"}, Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := f.d.CreatePreview(ownerCtx, team.ID, ownerID, "two-services", f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{local.ServiceID, shared.ID} {
		if _, err := f.d.AddPreviewService(ownerCtx, controlstate.AddPreviewServiceRequest{
			PreviewID: preview.ID, ServiceID: service, TeamID: team.ID, IdentityID: ownerID,
		}, f.now); err != nil {
			t.Fatal(err)
		}
	}
	member := f.membership(ownerID, team.ID)
	second := f.principal(secondOwner)
	if _, err := f.d.SetMembershipRole(controlstate.WithControlPrincipal(ctx, second), second.IdentityID, team.ID, member.ID, controlstate.TeamRoleMember, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.GetService(ownerCtx, shared.ID, ownerID); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatal("partial-share fixture retained management of the team-owned service", err)
	}
	if _, err := f.d.GetService(ownerCtx, local.ServiceID, ownerID); err != nil {
		t.Fatal("partial-share fixture lost management of the member-owned service", err)
	}
	// the preview still contains both services, but the demoted member manages
	// only their local service. state must reject the complete share atomically.
	h, err := NewHandler(Config{}, DatabaseStores(f.d), f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	create := func(ids []string, key string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(controlv1.CreateShareRequest{
			ServiceIds: ids, EntryServiceId: local.ServiceID, ExpiresAt: f.now.Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/v1/previews/"+preview.ID+"/shares", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+owner.AccessToken)
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	denied := create([]string{local.ServiceID, shared.ID}, "two-services")
	if denied.Code != http.StatusForbidden {
		t.Fatal("share creation did not recheck current service management", denied.Code)
	}
	var shares, captures int
	if err := f.sql.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.shares WHERE created_by_identity_id=$1),
		(SELECT count(*) FROM control.share_services WHERE service_id=ANY($2::text[]))`,
		ownerID, []string{local.ServiceID, shared.ID}).Scan(&shares, &captures); err != nil || shares != 0 || captures != 0 {
		t.Fatal("partial authorization persisted a share or captured service", shares, captures, err)
	}
	created := create([]string{local.ServiceID}, "local-only")
	var result controlv1.ShareCreation
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &result) != nil ||
		!slices.Equal(result.Share.ServiceIds, []string{local.ServiceID}) || result.Share.EntryServiceId != local.ServiceID ||
		created.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("member could not share their exact local service", created.Code)
	}
	secret, err := base64.RawURLEncoding.DecodeString(result.TokenSource.Secret)
	if err != nil || len(secret) != 32 {
		t.Fatal("share creation did not deliver its credential", err)
	}
	fingerprint := sha256.Sum256(secret)
	var stored []byte
	if err := f.sql.QueryRow(ctx, `SELECT secret_digest FROM control.shares WHERE id=$1`, result.Share.Id).Scan(&stored); err != nil || !bytes.Equal(stored, fingerprint[:]) {
		t.Fatal("share credential did not match the durable digest", err)
	}
	retry := create([]string{local.ServiceID}, "local-only")
	if retry.Code != http.StatusConflict || !strings.Contains(retry.Body.String(), result.Share.Id) ||
		strings.Contains(retry.Body.String(), result.TokenSource.Secret) || strings.Contains(retry.Body.String(), `"token_source"`) {
		t.Fatal("share retry redelivered a credential or lost the original resource", retry.Code, retry.Body.String())
	}
}
