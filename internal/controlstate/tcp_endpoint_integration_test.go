package controlstate

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestIntegrationDatabasePublicURLClaimsPortWithCreation(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "database_public_url")
	request := builtinRouteRequest(t, database, now)
	if err := database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", []int32{5432}, now); err != nil {
		t.Fatal(err)
	}
	request.Target, request.ServiceProtocol = "", PublicURLServicePostgres
	first, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil || first.ServiceProtocol != PublicURLServicePostgres || first.Target != "" || first.PublicPort == nil || *first.PublicPort != 5432 {
		t.Fatalf("saved PostgreSQL address = %#v, %v", first, err)
	}
	membership, err := controlstatedb.New(database.pool).GetActivePublishRunMembership(t.Context(), controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, _, err := database.CreatePublicURLPublishCredential(t.Context(), CreatePublicURLPublishCredentialRequest{
		PublicURLID: first.ID, TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
		MembershipID: request.MembershipID, PolicyRevision: uint64(membership.PolicyRevision),
		CertificatePlan: authorization.CertificatePlan{
			CacheKey: first.CanonicalHostname, Scope: first.CanonicalHostname,
			Identifiers: []string{first.CanonicalHostname}, ChallengeMethod: certificateidentity.ChallengeTLSALPN01,
		}, Now: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := database.ListTeamPublicURLPublishCredentials(t.Context(), request.TeamID, "")
	if err != nil || len(page.Credentials) != 1 || page.Credentials[0].ID != credential.ID ||
		page.Credentials[0].PublicURL != first.CanonicalHostname+":5432" {
		t.Fatalf("database credential address = %+v, %v", page, err)
	}
	repeated, err := database.CreatePublicURL(t.Context(), request, now.Add(time.Minute))
	if err != nil || repeated.PublicPort == nil || *repeated.PublicPort != 5432 || repeated.ID != first.ID {
		t.Fatalf("idempotent address = %#v, %v", repeated, err)
	}
	second := request
	second.IdempotencyKey = "second-db-endpoint"
	second.CanonicalHostname = "other." + request.CanonicalHostname
	if _, err := database.CreatePublicURL(t.Context(), second, now); !errors.Is(err, ErrTCPPortPoolFull) {
		t.Fatalf("exhausted pool saved an unusable URL: %v", err)
	}
	var count int
	if err := database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_urls WHERE canonical_hostname = $1`, second.CanonicalHostname).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed allocation left a saved URL: count=%d err=%v", count, err)
	}
	if err := database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", []int32{5432, 15432}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	created, err := database.CreatePublicURL(t.Context(), second, now.Add(time.Hour))
	if err != nil || created.PublicPort == nil || *created.PublicPort != 15432 {
		t.Fatalf("expanded pool address = %#v, %v", created, err)
	}
	if err := database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", []int32{5432, 15432, 3306}, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	mysql := request
	mysql.IdempotencyKey, mysql.CanonicalHostname, mysql.ServiceProtocol = "mysql-endpoint", "mysql."+request.CanonicalHostname, PublicURLServiceMySQL
	mysqlURL, err := database.CreatePublicURL(t.Context(), mysql, now.Add(2*time.Hour))
	if err != nil || mysqlURL.ServiceProtocol != PublicURLServiceMySQL || mysqlURL.PublicPort == nil || *mysqlURL.PublicPort != 3306 {
		t.Fatalf("saved MySQL address = %#v, %v", mysqlURL, err)
	}
}
