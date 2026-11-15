package state

import (
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationSharesSnapshotAndRevoke(t *testing.T) {
	f := newServiceHTTPFixture(t)
	database, now, service := f.database, f.now, f.service
	preview, err := database.CreatePreview(t.Context(), service.TeamID, f.project.ActorID, "preview", now)
	if err != nil {
		t.Fatal(err)
	}
	preview, err = database.AddPreviewService(t.Context(), AddPreviewServiceRequest{
		PreviewID: preview.ID, ServiceID: service.ID, TeamID: service.TeamID, IdentityID: f.project.ActorID,
	}, now)
	if err != nil || !slices.Equal(preview.ServiceIDs, []string{service.ID}) {
		t.Fatalf("preview = %+v, %v", preview, err)
	}
	secret := sha256.Sum256([]byte("secret supplied by client"))
	request := CreateShareRequest{
		PreviewID: preview.ID, TeamID: preview.TeamID, ActingIdentityID: f.project.ActorID,
		IdempotencyKey: "first-share", SecretFingerprint: secret, ExpiresAt: now.Add(24 * time.Hour),
		ServiceIDs: []string{service.ID}, EntryServiceID: service.ID,
	}
	for _, expiresAt := range []time.Time{now, now.Add(31 * 24 * time.Hour)} {
		invalid := request
		invalid.ExpiresAt = expiresAt
		if _, err := database.CreateShare(t.Context(), invalid, now); !errors.Is(err, ErrShareInvalid) {
			t.Fatalf("invalid expiration %s: %v", expiresAt, err)
		}
	}
	share, err := database.CreateShare(t.Context(), request, now)
	if err != nil || share.ID == "" || share.PreviewID != preview.ID || share.EntryServiceID != service.ID || !slices.Equal(share.ServiceIDs, []string{service.ID}) || share.RevokedAt != nil {
		t.Fatalf("created share = %+v, %v", share, err)
	}
	assertRetry := func(at time.Time) {
		t.Helper()
		_, err := database.CreateShare(t.Context(), request, at)
		var delivery *CredentialDeliveryUnavailable
		if !errors.As(err, &delivery) || delivery.ResourceID != share.ID {
			t.Fatalf("retry did not identify the original share: %v", err)
		}
	}
	assertRetry(now)
	changed := request
	changed.Label = "different label"
	if _, err := database.CreateShare(t.Context(), changed, now); !errors.Is(err, ErrShareIdempotency) {
		t.Fatalf("same key with different input: %v", err)
	}
	added := f.local(t, "api", nil)
	_, err = database.AddPreviewService(t.Context(), AddPreviewServiceRequest{
		PreviewID: preview.ID, ServiceID: added.ID, TeamID: service.TeamID, IdentityID: f.project.ActorID,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := database.GetShare(t.Context(), share.ID)
	if err != nil || saved.EntryServiceID != service.ID || !slices.Equal(saved.ServiceIDs, []string{service.ID}) {
		t.Fatalf("share gained a new hostname after creation: %+v, %v", saved, err)
	}
	page, err := database.ListShares(t.Context(), preview.ID, "")
	if err != nil || len(page.Shares) != 1 || page.Shares[0].ID != share.ID || page.NextCursor != "" {
		t.Fatalf("share list = %+v, %v", page, err)
	}
	teamPage, err := database.ListTeamShares(t.Context(), preview.TeamID, f.project.ActorID, "")
	if err != nil || len(teamPage.Shares) != 1 || teamPage.Shares[0].ID != share.ID {
		t.Fatalf("creator's team shares = %+v, %v", teamPage, err)
	}
	otherPage, err := database.ListTeamShares(t.Context(), preview.TeamID, "other-identity", "")
	if !errors.Is(err, ErrServiceAccess) || len(otherPage.Shares) != 0 {
		t.Fatalf("another identity's team shares = %+v, %v", otherPage, err)
	}
	if _, err := database.RevokeShare(t.Context(), share.ID, "other-identity", now); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("other identity revoked share: %v", err)
	}
	revoked, err := database.RevokeShare(t.Context(), share.ID, f.project.ActorID, now.Add(time.Minute))
	if err != nil || revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(now.Add(time.Minute).UTC().Truncate(time.Microsecond)) {
		t.Fatalf("revoked share = %+v, %v", revoked, err)
	}
	again, err := database.RevokeShare(t.Context(), share.ID, f.project.ActorID, now.Add(time.Hour))
	if err != nil || again.RevokedAt == nil || !again.RevokedAt.Equal(*revoked.RevokedAt) {
		t.Fatalf("repeated revoke = %+v, %v", again, err)
	}
	assertRetry(now)
	assertRetry(request.ExpiresAt.Add(time.Minute))
}

func TestIntegrationShareRejectsStaleOrUnrelatedURLs(t *testing.T) {
	f := newServiceHTTPFixture(t)
	database, now, service := f.database, f.now, f.service
	preview, err := database.CreatePreview(t.Context(), service.TeamID, f.project.ActorID, "preview", now)
	if err != nil {
		t.Fatal(err)
	}
	request := CreateShareRequest{
		PreviewID: preview.ID, TeamID: service.TeamID, ActingIdentityID: f.project.ActorID,
		IdempotencyKey: "share", SecretFingerprint: sha256.Sum256([]byte("new secret")), ExpiresAt: now.Add(time.Hour),
		ServiceIDs: []string{service.ID}, EntryServiceID: service.ID,
	}
	if _, err := database.CreateShare(t.Context(), request, now); !errors.Is(err, ErrShareStale) {
		t.Fatalf("public URL outside preview was shared: %v", err)
	}
	_, err = database.AddPreviewService(t.Context(), AddPreviewServiceRequest{
		PreviewID: preview.ID, ServiceID: service.ID, TeamID: service.TeamID, IdentityID: f.project.ActorID,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.services SET enabled=false WHERE id=$1`, service.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateShare(t.Context(), request, now); !errors.Is(err, ErrShareStale) {
		t.Fatalf("stale service eligibility was shared: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.services SET enabled=true WHERE id=$1`, service.ID); err != nil {
		t.Fatal(err)
	}
	request.ActingIdentityID = "other-identity"
	if _, err := database.CreateShare(t.Context(), request, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("other identity used preview: %v", err)
	}
}

func TestIntegrationExactAndPreviewShareSnapshotsHaveDifferentScopes(t *testing.T) {
	f := newServiceHTTPFixture(t)
	database, now, first := f.database, f.now, f.service
	second := f.local(t, "api", nil)
	preview := f.preview(t, "two-services", first, second)
	create := CreateShareRequest{
		TeamID: first.TeamID, ActingIdentityID: f.project.ActorID, IdempotencyKey: "exact",
		SecretFingerprint: sha256.Sum256([]byte("exact")), ExpiresAt: now.Add(time.Hour),
		ServiceIDs: []string{first.ID}, EntryServiceID: first.ID,
	}
	exact, err := database.CreateShare(t.Context(), create, now)
	if err != nil || exact.Scope != "service" || exact.PreviewID != "" || !slices.Equal(exact.ServiceIDs, []string{first.ID}) {
		t.Fatalf("exact snapshot = %+v, %v", exact, err)
	}
	create.PreviewID, create.IdempotencyKey = preview.ID, "preview"
	create.ServiceIDs = append(create.ServiceIDs, second.ID)
	wide, err := database.CreateShare(t.Context(), create, now)
	if err != nil || wide.Scope != "preview" || wide.PreviewID != preview.ID || len(wide.ServiceIDs) != 2 {
		t.Fatalf("preview snapshot = %+v, %v", wide, err)
	}
	if _, err := controlstatedb.New(database.pool).GetActiveShareForService(t.Context(), controlstatedb.GetActiveShareForServiceParams{
		ShareID: exact.ID, ServiceID: second.ID, Now: timestamptz(now),
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("exact share opened the other preview URL: %v", err)
	}
}
