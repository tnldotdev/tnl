package controlstate

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestIntegrationVisitorInventoryDistinguishesMembershipAndShares(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "visitor_inventory")
	request := builtinRouteRequest(t, database, now)
	web := createTestPublicURL(t, database, request, now)
	if err := database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", []int32{5432}, now); err != nil {
		t.Fatal(err)
	}
	databaseRequest := request
	databaseRequest.IdempotencyKey = "visitor-inventory-database"
	databaseRequest.RequestDigest = sha256.Sum256([]byte(databaseRequest.IdempotencyKey))
	databaseRequest.CanonicalHostname = "db." + request.CanonicalHostname
	databaseRequest.ServiceProtocol, databaseRequest.Target = PublicURLServicePostgres, ""
	postgres := createTestPublicURL(t, database, databaseRequest, now)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET kind = 'organization' WHERE id = $1`, request.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, database, now, request.ActingIdentityID, request.TeamID, "inventory-member", TeamRoleMember)
	visitor, err := database.EnsureServiceIdentity(t.Context(), "tunnels.example.test", OIDCIdentity{
		Issuer: "https://account.example", Subject: "external-inventory", DisplayName: "External reviewer",
		NormalizedEmail: "reviewer@example.com", EmailVerified: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	list := func(identityID string, at time.Time) AvailablePublicURLPage {
		t.Helper()
		page, err := database.ListAvailablePublicURLs(t.Context(), identityID, "", "", at)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	access := func(page AvailablePublicURLPage) map[string]string {
		result := make(map[string]string, len(page.PublicURLs))
		for _, url := range page.PublicURLs {
			result[url.ID] = url.VisitorAccess
		}
		return result
	}
	if page := list(request.ActingIdentityID, now); len(page.PublicURLs) != 2 || access(page)[web.ID] != "owner" || access(page)[postgres.ID] != "owner" {
		t.Fatalf("owner inventory = %+v", page)
	}
	if page := list(member.IdentityID, now); len(page.PublicURLs) != 2 || access(page)[web.ID] != "inventory" || access(page)[postgres.ID] != "inventory" {
		t.Fatalf("ordinary member inventory = %+v", page)
	}
	if page := list(visitor.Identity.ID, now); len(page.PublicURLs) != 0 {
		t.Fatalf("external identity saw unshared URLs = %+v", page)
	}
	digest := sha256.Sum256([]byte("visitor inventory grant"))
	insert := func(id, kind, previewID, publicURLID, identityID string, expires time.Time) {
		t.Helper()
		_, err := database.pool.Exec(t.Context(), `INSERT INTO control.visitor_access_grants
			(id, team_id, kind, preview_id, public_url_id, identity_id, created_by_identity_id,
			 idempotency_key, request_digest, created_at, expires_at)
			VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), $7, $1, $8, $9, $10)`,
			id, request.TeamID, kind, previewID, publicURLID, identityID, request.ActingIdentityID, digest[:], now, expires)
		if err != nil {
			t.Fatal(err)
		}
	}
	preview, err := database.CreatePreview(t.Context(), request.TeamID, request.ActingIdentityID, "inventory-preview", now)
	if err != nil {
		t.Fatal(err)
	}
	team, err := database.GetTeam(t.Context(), request.ActingIdentityID, request.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
		PublicURLID: web.ID, PolicyRevision: uint64(team.PolicyRevision), ExpectedMutationRevision: web.MutationRevision,
	}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), AddPreviewPublicURLRequest{
		PreviewID: preview.ID, TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
		PublicURLID: postgres.ID, PolicyRevision: uint64(team.PolicyRevision), ExpectedMutationRevision: postgres.MutationRevision,
	}, now); err != nil {
		t.Fatal(err)
	}
	insert("grant-preview", "team_preview", preview.ID, "", "", now.Add(time.Hour))
	if page := list(member.IdentityID, now); len(page.PublicURLs) != 2 || access(page)[web.ID] != "team" || access(page)[postgres.ID] != "inventory" {
		t.Fatalf("preview share reached database = %+v", page)
	}
	insert("grant-database", "team_url", "", postgres.ID, "", now.Add(time.Hour))
	if page := list(member.IdentityID, now); len(page.PublicURLs) != 2 || access(page)[postgres.ID] != "team" {
		t.Fatalf("deliberate database team share = %+v", page)
	}
	insert("grant-invite", "identity_url", "", postgres.ID, visitor.Identity.ID, now.Add(time.Hour))
	if page := list(visitor.Identity.ID, now); len(page.PublicURLs) != 1 || page.PublicURLs[0].ID != postgres.ID || page.PublicURLs[0].VisitorAccess != "invite" || page.PublicURLs[0].PublicPort == nil {
		t.Fatalf("external invite inventory = %+v", page)
	}
	if page := list(visitor.Identity.ID, now.Add(2*time.Hour)); len(page.PublicURLs) != 0 {
		t.Fatalf("expired invite still visible = %+v", page)
	}
	if page, err := database.ListAvailablePublicURLs(t.Context(), member.IdentityID, visitor.PersonalTeamID, "", now); err != nil || len(page.PublicURLs) != 0 {
		t.Fatalf("team filter leaked URLs = %+v, %v", page, err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.visitor_access_grants SET revoked_at = $2, revoked_by_identity_id = $3 WHERE id = $1`,
		"grant-invite", now.Add(time.Minute), request.ActingIdentityID); err != nil {
		t.Fatal(err)
	}
	if page := list(visitor.Identity.ID, now.Add(time.Minute)); len(page.PublicURLs) != 0 {
		t.Fatalf("revoked invite still visible = %+v", page)
	}
	if err := database.RemoveMembership(t.Context(), request.ActingIdentityID, request.TeamID, member.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if page := list(member.IdentityID, now.Add(time.Minute)); len(page.PublicURLs) != 0 {
		t.Fatalf("removed member still saw the team's public URLs = %+v", page)
	}
}
