package controlstate

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntegrationSavedAliasTargetStaysLocalThroughPolicyUpdates(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "alias_local_target")
	request := oidcRouteRequest(t, d, now)
	request.Purpose, request.Target, request.ServiceProtocol = PublicURLPurposeAlias, "", PublicURLServiceHTTP
	route, err := d.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := d.UpdateAuthorizedPublicURL(t.Context(), AuthorizedPublicURLUpdateRequest{
		PublicURLID: route.ID, TeamID: route.TeamID, ActingIdentityID: request.ActingIdentityID,
		Target: "", AllowedIPPrefixes: []string{"192.0.2.10/32"}, PolicyRevision: uint64(route.PolicyRevision), ExpectedMutationRevision: route.MutationRevision,
	}, now.Add(time.Second))
	if err != nil || updated.Target != "" || updated.Purpose != PublicURLPurposeAlias || updated.MutationRevision <= route.MutationRevision {
		t.Fatalf("alias policy update changed its target ownership: %+v, %v", updated, err)
	}
	for _, test := range []struct {
		purpose   string
		ephemeral bool
	}{
		{"app", true}, {"alias", true}, {"oauth", false}, {"webhooks", false}, {"demo", false}, {"unknown", false},
	} {
		t.Run(test.purpose, func(t *testing.T) {
			const statement = `UPDATE control.public_urls SET purpose=$2,ephemeral=$3,expires_at=CASE WHEN $3 THEN created_at+interval '1 hour' ELSE NULL END,target=$4 WHERE id=$1`
			_, err := d.pool.Exec(t.Context(), statement, route.ID, test.purpose, test.ephemeral, "")
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "23514" {
				t.Fatalf("database accepted an invalid targetless URL: %v", err)
			}
			if test.purpose == "unknown" {
				return
			}
			tx, err := d.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			if _, err := tx.Exec(t.Context(), statement, route.ID, test.purpose, test.ephemeral, "http://127.0.0.1:3000"); err != nil {
				t.Fatalf("nonempty target failed another shape constraint: %v", err)
			}
		})
	}
}
