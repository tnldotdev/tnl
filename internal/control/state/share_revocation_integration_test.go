package state

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func shareTeamVisitorAllowed(t *testing.T, f serviceHTTPFixture, principal ControlPrincipal) bool {
	t.Helper()
	ctx := WithControlPrincipal(t.Context(), principal)
	tx, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	permission, err := f.database.serviceHTTPIdentityPermission(ctx, tx, f.service.ID, principal.IdentityID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return permission.VisitAllowed
}

func TestIntegrationShareAndTeamAccessRevocationRetainsUnavailableServiceOwnership(t *testing.T) {
	for _, state := range []string{"disabled", "deleted"} {
		t.Run(state, func(t *testing.T) {
			f := ordinaryShareFixture(t, "organization")
			d, owner := f.database, f.project.ActorID
			_, creator := allocationVisitorMember(t, d, f.project.TeamID, owner, "share-creator", TeamRoleAdmin, f.now)
			visitorSession, outsider := allocationVisitorMember(t, d, f.project.TeamID, owner, "share-visitor", TeamRoleMember, f.now)
			f.project.ActorID = creator.IdentityID
			createService := func(name string) ServiceRecord {
				t.Helper()
				service, err := d.CreateServiceAt(t.Context(), f.project.TeamID, creator.IdentityID, name, name, ServicePlacement{},
					f.now, ServiceMetadata{Protocol: "http"}, &ProjectServiceConfiguration{Target: "localhost:3000", Public: new(true)})
				if err != nil {
					t.Fatal(err)
				}
				return service
			}
			f.service = createService("creatorweb")
			api := createService("creatorapi")
			if _, err := d.SetMembershipRole(t.Context(), owner, f.project.TeamID, creator.ID, TeamRoleMember, f.now); err != nil {
				t.Fatal(err)
			}
			f.run = f.publish(t, f.service)
			apiRun := f.publish(t, api)
			parent := shareCreatorSession(t, f, time.Hour, 48*time.Hour)
			creatorCtx := WithControlPrincipal(t.Context(), companyTestPrincipal(t, d, parent, f.now))
			visitor := companyTestPrincipal(t, d, visitorSession, f.now)
			visitorCtx := WithControlPrincipal(t.Context(), visitor)
			preview := f.preview(t, "revocable-preview", f.service, api)
			teamRequest := SetPreviewTeamAccessRequest{PreviewID: preview.ID, TeamID: f.project.TeamID,
				IdentityID: creator.IdentityID, Enabled: true}
			if shareTeamVisitorAllowed(t, f, visitor) {
				t.Fatal("unrelated member had access before the team grant")
			}
			if _, err := d.SetPreviewTeamAccess(creatorCtx, teamRequest, f.now); err != nil {
				t.Fatal(err)
			}
			raw := sha256.Sum256([]byte("revocable share secret"))
			shareRequest := CreateShareRequest{PreviewID: preview.ID, TeamID: f.project.TeamID, ActingIdentityID: creator.IdentityID,
				IdempotencyKey: "revocable-share", SecretFingerprint: sha256.Sum256(raw[:]), ExpiresAt: f.now.Add(24 * time.Hour),
				ServiceIDs: []string{f.service.ID, api.ID}, EntryServiceID: f.service.ID}
			share, err := d.CreateShare(creatorCtx, shareRequest, f.now)
			if err != nil {
				t.Fatal(err)
			}
			redeemed, err := d.RedeemShare(t.Context(), f.auth(), share.ID, raw[:], nil, f.now)
			if err != nil {
				t.Fatal(err)
			}
			assertShareSources(t, f, share, raw[:], redeemed.CookieSecret, f.now, true)
			if !shareTeamVisitorAllowed(t, f, visitor) {
				t.Fatal("team grant did not authorize the live sibling")
			}

			denyUnrelated := func() {
				t.Helper()
				request := teamRequest
				request.IdentityID, request.Enabled = outsider.IdentityID, false
				if _, err := d.SetPreviewTeamAccess(visitorCtx, request, f.now); !errors.Is(err, ErrPreviewAccess) {
					t.Fatal("unrelated member disabled another creator's team access", err)
				}
				if _, err := d.RevokeShare(visitorCtx, share.ID, outsider.IdentityID, f.now); !errors.Is(err, ErrShareNotFound) {
					t.Fatal("unrelated member revoked another creator's share", err)
				}
			}
			denyUnrelated()
			if state == "disabled" {
				if _, err := d.SetServiceEnabled(creatorCtx, api.ID, creator.IdentityID, false, f.now); err != nil {
					t.Fatal(err)
				}
			} else if err := d.DeleteService(creatorCtx, api.ID, creator.IdentityID, ServiceDeleteConditions{Unconditional: true}, f.now); err != nil {
				t.Fatal(err)
			}
			denyUnrelated()
			var webLive, apiClosed bool
			if err := d.pool.QueryRow(t.Context(), `SELECT
				EXISTS(SELECT 1 FROM control.service_runs run JOIN control.services service ON service.id=run.service_id
					WHERE run.id=$1 AND service.enabled AND run.state='ready' AND run.healthy AND run.closed_at IS NULL
					AND run.publisher_expires_at>$3 AND run.certificate_expires_at>$3),
				EXISTS(SELECT 1 FROM control.service_runs WHERE id=$2 AND closed_at IS NOT NULL)`,
				f.run.RunID, apiRun.RunID, f.now).Scan(&webLive, &apiClosed); err != nil || !webLive || !apiClosed {
				t.Fatal("fixture did not retain a ready sibling and close the unavailable service", webLive, apiClosed, err)
			}
			// availability still gates granting; revocation must not accidentally
			// turn a deleted or disabled captured service into a new grant.
			if _, err := d.SetPreviewTeamAccess(creatorCtx, teamRequest, f.now); !errors.Is(err, ErrPreviewStale) {
				t.Fatal("unavailable captured service enabled team access", err)
			}
			shareRequest.IdempotencyKey = "unavailable-share"
			if _, err := d.CreateShare(creatorCtx, shareRequest, f.now); !errors.Is(err, ErrShareStale) {
				t.Fatal("unavailable captured service created a new share", err)
			}
			if !shareTeamVisitorAllowed(t, f, visitor) {
				t.Fatal("unavailable sibling alone removed the live sibling's team grant")
			}
			teamRequest.Enabled = false
			disabled, teamErr := d.SetPreviewTeamAccess(creatorCtx, teamRequest, f.now)
			if teamErr != nil || disabled.TeamAccessEnabled {
				t.Error("current creator could not disable team access with an unavailable captured service", teamErr)
			}
			revoked, shareErr := d.RevokeShare(creatorCtx, share.ID, creator.IdentityID, f.now)
			if shareErr != nil || revoked.RevokedAt == nil {
				t.Error("current creator could not revoke a share with an unavailable captured service", shareErr)
			}
			if t.Failed() {
				return
			}
			if shareTeamVisitorAllowed(t, f, visitor) {
				t.Fatal("disabled team grant still authorized the live sibling")
			}
			assertShareSources(t, f, share, raw[:], redeemed.CookieSecret, f.now, false)
			// the creator is an ordinary member, not an administrator. losing
			// the retained namespace receipt still fences both revoke operations,
			// even when retrying an already completed revocation.
			if _, err := d.pool.Exec(t.Context(), `UPDATE control.service_namespace_claims SET membership_id=$2 WHERE namespace=$1`,
				api.Endpoint.Hostname, outsider.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := d.SetPreviewTeamAccess(creatorCtx, teamRequest, f.now); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("stale captured ownership disabled team access", err)
			}
			if _, err := d.RevokeShare(creatorCtx, share.ID, creator.IdentityID, f.now); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("stale captured ownership revoked the share", err)
			}
			savedPreview, err := d.GetPreview(t.Context(), preview.ID)
			if err != nil || savedPreview.TeamAccessEnabled {
				t.Fatal("denied revocation changed the preview grant", err)
			}
			savedShare, err := d.GetShare(t.Context(), share.ID)
			if err != nil || savedShare.RevokedAt == nil || !savedShare.RevokedAt.Equal(*revoked.RevokedAt) {
				t.Fatal("denied revocation changed the share", err)
			}
			if _, err := d.pool.Exec(t.Context(), `UPDATE control.service_namespace_claims SET membership_id=$2 WHERE namespace=$1`,
				api.Endpoint.Hostname, creator.ID); err != nil {
				t.Fatal(err)
			}
			if state == "disabled" {
				if _, err := d.SetServiceEnabled(creatorCtx, api.ID, creator.IdentityID, true, f.now); err != nil {
					t.Fatal(err)
				}
				assertShareSources(t, f, share, raw[:], redeemed.CookieSecret, f.now, false)
				if shareTeamVisitorAllowed(t, f, visitor) {
					t.Fatal("re-enabling the sibling revived revoked team access")
				}
			}
			// cleanup is idempotent without requiring a live captured service.
			if _, err := d.SetPreviewTeamAccess(creatorCtx, teamRequest, f.now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			again, err := d.RevokeShare(creatorCtx, share.ID, creator.IdentityID, f.now.Add(time.Second))
			if err != nil || again.RevokedAt == nil || !again.RevokedAt.Equal(*revoked.RevokedAt) {
				t.Fatal("repeated revoke changed the original revocation", err)
			}
		})
	}
}
