package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func inventoryHTTPService(t *testing.T, d *Database, owner, team, name string, public, anonymous bool, now time.Time) ServiceRecord {
	t.Helper()
	mode := "restricted"
	if anonymous {
		mode = "anonymous"
	}
	service, err := d.CreateServiceAt(t.Context(), team, owner, name, name, ServicePlacement{}, now, ServiceMetadata{},
		&ProjectServiceConfiguration{Target: "127.0.0.1:3000", Protocol: "http", Public: &public,
			HTTP: &config.HTTPService{Access: &config.Access{Mode: mode}}})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func inventorySessionContext(t *testing.T, d *Database, identity string, now time.Time) context.Context {
	t.Helper()
	session := browserTestControlSession(t, d, identity, now)
	return WithControlPrincipal(t.Context(), companyTestPrincipal(t, d, session, now))
}

func TestIntegrationServiceInventorySeparatesPreviewAndConnectorDiscovery(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	member := addAuthorityMember(t, d, now, owner, team.ID, "inventory-member", TeamRoleMember)
	ctx := inventorySessionContext(t, d, member.IdentityID, now)
	previewOnly := inventoryHTTPService(t, d, owner, team.ID, "preview-web", true, false, now)
	connectorOnly := inventoryHTTPService(t, d, owner, team.ID, "connector-web", false, false, now)
	otherRequest := authorityTeamRequest(owner)
	otherRequest.DisplayName = "undisclosed-inventory-team"
	otherRequest.IdempotencyKey = "undisclosed-team"
	otherRequest.RequestDigest = sha256.Sum256([]byte("undisclosed-team"))
	otherTeam, err := d.CreateTeam(t.Context(), otherRequest, now)
	if err != nil {
		t.Fatal(err)
	}
	anonymous := inventoryHTTPService(t, d, owner, otherTeam.ID, "undisclosed-anonymous", true, true, now)
	preview, err := d.CreatePreview(t.Context(), team.ID, owner, "inventory-preview", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.AddPreviewService(t.Context(), AddPreviewServiceRequest{PreviewID: preview.ID, TeamID: team.ID, IdentityID: owner, ServiceID: previewOnly.ID}, now); err != nil {
		t.Fatal(err)
	}
	request := SetPreviewTeamAccessRequest{PreviewID: preview.ID, TeamID: team.ID, IdentityID: owner, Enabled: true}
	if _, err = d.SetPreviewTeamAccess(t.Context(), request, now); err != nil {
		t.Fatal(err)
	}
	native, next, err := d.ListAvailableServices(ctx, member.IdentityID, "", controlv1.ServiceAccessPathConnector, now)
	if err != nil || len(native) != 0 || next != "" {
		t.Fatal("preview-team permission became connector discovery", native, next, err)
	}
	public, next, err := d.ListAvailableServices(ctx, member.IdentityID, "", controlv1.ServiceAccessPathPublicEndpoint, now)
	if err != nil || len(public) != 1 || next != "" || public[0].ID != previewOnly.ID || public[0].VisitorAccess != "preview_team" ||
		public[0].TeamName != team.DisplayName || public[0].ServiceRunID != "" {
		t.Fatal("public inventory lost its exact preview permission, actual team name, or offline service", public, next, err)
	}
	encoded, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	for _, denied := range []string{otherTeam.ID, otherTeam.DisplayName, anonymous.ID, anonymous.Name, anonymous.Endpoint.Hostname} {
		if bytes.Contains(encoded, []byte(denied)) {
			t.Fatal("anonymous service disclosed team or service metadata through inventory")
		}
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	permission, permissionErr := d.serviceHTTPIdentityPermission(ctx, tx, anonymous.ID, member.IdentityID, now)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if permissionErr != nil || !permission.VisitAllowed || permission.Reason != "anonymous" {
		t.Fatal("inventory exclusion changed ordinary anonymous HTTP permission", permission, permissionErr)
	}
	if _, err = d.CreateServiceGrant(t.Context(), connectorOnly.ID, owner, "connector-only-grant", "identity", member.IdentityID, nil, now); err != nil {
		t.Fatal(err)
	}
	native, _, err = d.ListAvailableServices(ctx, member.IdentityID, "", controlv1.ServiceAccessPathConnector, now)
	if err != nil || len(native) != 1 || native[0].ID != connectorOnly.ID || native[0].VisitorAccess != "identity_grant" {
		t.Fatal("connector inventory lost its own current identity grant", native, err)
	}
	request.Enabled = false
	if _, err = d.SetPreviewTeamAccess(t.Context(), request, now); err != nil {
		t.Fatal(err)
	}
	public, next, err = d.ListAvailableServices(ctx, member.IdentityID, "", controlv1.ServiceAccessPathPublicEndpoint, now)
	if err != nil || len(public) != 0 || next != "" {
		t.Fatal("revoked preview, connector-only service, or anonymous service remained discoverable", public, next, err)
	}
}

func TestIntegrationServiceInventoryAuthorizesSparsePagesBeforeCursor(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	member := addAuthorityMember(t, d, now, owner, team.ID, "sparse-member", TeamRoleMember)
	ctx := inventorySessionContext(t, d, member.IdentityID, now)
	services := make([]ServiceRecord, 205)
	for i := range services {
		services[i] = inventoryHTTPService(t, d, owner, team.ID, fmt.Sprintf("inventory-%03d", i), true, true, now)
	}
	slices.SortFunc(services, func(a, b ServiceRecord) int { return strings.Compare(a.ID, b.ID) })
	// the first complete candidate batch, plus one, is anonymous-only. later
	// services have actual identity grants despite sharing that HTTP policy.
	for _, service := range services[102:] {
		if _, err := d.CreateServiceGrant(t.Context(), service.ID, owner, service.ID, "identity", member.IdentityID, nil, now); err != nil {
			t.Fatal(err)
		}
	}
	// multiple current permission sources must not duplicate a service.
	if _, err := d.CreateServiceGrant(t.Context(), services[204].ID, owner, "also-team", "team", "", nil, now); err != nil {
		t.Fatal(err)
	}
	first, cursor, err := d.ListAvailableServices(ctx, member.IdentityID, "", controlv1.ServiceAccessPathPublicEndpoint, now)
	if err != nil || len(first) != 100 || cursor != services[201].ID {
		t.Fatal("denied candidates truncated the authorized page or moved its cursor", len(first), cursor, err)
	}
	second, next, err := d.ListAvailableServices(ctx, member.IdentityID, cursor, controlv1.ServiceAccessPathPublicEndpoint, now)
	if err != nil || len(second) != 3 || next != "" {
		t.Fatal("authorized lookahead was skipped, duplicated, or gave a false next page", len(second), next, err)
	}
	all := append(first, second...)
	for i, row := range all {
		if row.ID != services[102+i].ID || row.TeamID != team.ID || row.TeamName != team.DisplayName || row.VisitorAccess == "" || row.VisitorAccess == "anonymous" ||
			row.ServiceRunID != "" || row.RunNumber != 0 || row.TLS != nil {
			t.Fatal("inventory changed identity, permission facts, offline state, or exposed publisher trust", i, row)
		}
	}
	encoded, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	for _, denied := range services[:102] {
		for _, secret := range []string{denied.ID, denied.Name, denied.Endpoint.Hostname} {
			if bytes.Contains(encoded, []byte(secret)) {
				t.Fatal("denied candidate leaked service metadata across pagination")
			}
		}
	}
}

func TestIntegrationServiceInventoryRetainsActualCompanySessionContext(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	service := inventoryHTTPService(t, d, owner, team.ID, "company-web", true, false, now)
	initial := browserTestControlSession(t, d, owner, now)
	connection := companyTestConnection(t, d, team.ID, companyTestPrincipal(t, d, initial, now), "approval", now)
	identity, err := companyBindTestIntent(t, d, OIDCIdentity{
		Issuer: connection.Issuer, Subject: owner, DisplayName: owner,
		AssertionDigest: sha256.Sum256([]byte("inventory-company-session")), AssertionExpiry: now.Add(time.Hour),
		TeamContexts: []oidc.TeamContext{{TeamID: team.ID, IdentityConnectionID: connection.ID, ConnectionRevision: connection.Revision,
			SourceID: connection.SourceID, Subject: "directory/" + owner, AuthenticatedAt: now.Unix()}},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	current, err := d.CreateOIDCControlSession(t.Context(), "tunnels.example.test", identity, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithControlPrincipal(t.Context(), companyTestPrincipal(t, d, current, now))
	for _, path := range []controlv1.ServiceAccessPath{controlv1.ServiceAccessPathConnector, controlv1.ServiceAccessPathPublicEndpoint} {
		rows, _, err := d.ListAvailableServices(ctx, owner, "", path, now)
		if err != nil || len(rows) != 1 || rows[0].ID != service.ID {
			t.Fatal("listing lost actual current company authentication", path, rows, err)
		}
		rows, _, err = d.ListAvailableServices(t.Context(), owner, "", path, now)
		if err != nil || len(rows) != 0 {
			t.Fatal("listing fabricated a company session from identity or manager access", path, rows, err)
		}
	}
}

func TestIntegrationServiceInventoryPreservesCertificateAndServiceHorizons(t *testing.T) {
	f := newServiceHTTPFixture(t)
	d, now := f.database, f.now
	service := inventoryHTTPService(t, d, f.project.ActorID, f.project.TeamID, "inventory-horizon", true, false, now)
	run := f.publish(t, service)
	ctx := inventorySessionContext(t, d, f.project.ActorID, now)
	check := func(at time.Time, listed, ready bool) {
		t.Helper()
		for _, path := range []controlv1.ServiceAccessPath{controlv1.ServiceAccessPathConnector, controlv1.ServiceAccessPathPublicEndpoint} {
			rows, _, err := d.ListAvailableServices(ctx, f.project.ActorID, "", path, at)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, row := range rows {
				if row.ID != service.ID {
					continue
				}
				found = true
				if (row.ServiceRunID != "") != ready || ready && (row.ServiceRunID != run.RunID || row.RunNumber != run.RunNumber) || !ready && row.RunNumber != 0 {
					t.Fatal("inventory advertised a run outside its current readiness horizon", path, row)
				}
			}
			if found != listed {
				t.Fatal("inventory confused saved-service discovery with current serving readiness", path, found, listed)
			}
		}
	}
	check(now, true, true)
	deadline := now.Add(time.Second)
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET certificate_expires_at=$2 WHERE id=$1`, run.RunID, deadline); err != nil {
		t.Fatal(err)
	}
	check(deadline, true, false)
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET certificate_expires_at=$2 WHERE id=$1`, run.RunID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.services SET expires_at=$2 WHERE id=$1`, service.ID, deadline); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := d.pool.QueryRow(ctx, `SELECT state FROM control.service_runs WHERE id=$1`, run.RunID).Scan(&state); err != nil || state != "ready" {
		t.Fatal("horizon fixture depended on a cleanup worker demoting the ready row", state, err)
	}
	check(deadline, false, false)
}
