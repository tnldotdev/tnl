package controlstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestIntegrationHostedPolicyRevocation(t *testing.T) {
	database, now := newCertificatePlanDatabase(t)
	const issuer, team, identity = "https://authority.example.test", "team_revocation", "identity_revocation"
	secret, err := database.EnsureExternalAuthorityPrincipal(t.Context(), identity, now)
	if err != nil {
		t.Fatal(err)
	}
	routes := make(map[string]PublicURL)
	sessions := make(map[string]PublishRunSetup)
	for _, name := range []string{"a", "b", "c", "d"} {
		domain := "domain_revocation"
		if name == "c" || name == "d" {
			domain = "domain_other"
		}
		route := createTestPublicURL(t, database, CreatePublicURLRequest{TeamID: team, DomainID: domain, ActingIdentityID: identity,
			IdempotencyKey: name, RequestDigest: sha256.Sum256([]byte(name)), CanonicalHostname: name + ".example.test",
			Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeShared, DNSState: PublicURLDNSUnmanaged, AuthorityIssuer: issuer, PolicyRevision: 5}, now)
		routes[name] = route
		if name == "c" {
			continue
		}
		setup, err := database.CreatePublishRun(t.Context(), PublishRunRequest{PublicURLID: route.ID, TeamID: team, MembershipID: "membership_" + name, ActingIdentityID: identity,
			RetrySecret: secret[:], IdempotencyKey: name, RequestDigest: sha256.Sum256([]byte(name)), AuthorityIssuer: issuer, PolicyRevision: 5,
			ExpectedMutationRevision: route.MutationRevision, CertificateCacheKey: route.CanonicalHostname, CertificateScope: "route",
			CertificateIdentifiers: []string{route.CanonicalHostname}, CertificateChallenge: "dns-01"}, now, time.Hour, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		sessions[name] = setup
	}
	routeC := routes["c"]
	update := AuthorizedPublicURLUpdateRequest{PublicURLID: routeC.ID, TeamID: team, ActingIdentityID: identity, Target: routeC.Target, AllowedIPPrefixes: []string{}, AuthorityIssuer: issuer, PolicyRevision: 6, ExpectedMutationRevision: routeC.MutationRevision}
	routeC, err = database.UpdateAuthorizedPublicURL(t.Context(), update, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	observed, applied := readAuthorityRevisions(t, database, issuer, team)
	if observed != 6 || applied != 0 {
		t.Fatalf("observed/applied revisions = %d/%d", observed, applied)
	}
	if _, err := database.CreatePublicURL(t.Context(), CreatePublicURLRequest{TeamID: team, DomainID: "domain_revocation", ActingIdentityID: identity,
		IdempotencyKey: "stale", RequestDigest: sha256.Sum256([]byte("stale")), CanonicalHostname: "stale.example.test", Target: routeC.Target,
		PublicURLScope: PublicURLScopeShared, DNSState: PublicURLDNSUnmanaged, AuthorityIssuer: issuer, PolicyRevision: 5}, now); !errors.Is(err, ErrPublicURLAuthority) {
		t.Fatalf("stale observed authority: %v", err)
	}
	ok, closed, err := database.ApplyHostedPolicyRevocation(t.Context(), issuer, team, 6, false, []string{"membership_a"}, nil, now.Add(time.Second))
	if err != nil || !ok || closed != 1 {
		t.Fatalf("membership revocation = %t/%d, %v", ok, closed, err)
	}
	observed, applied = readAuthorityRevisions(t, database, issuer, team)
	if observed != 6 || applied != 6 {
		t.Fatalf("applied revisions = %d/%d", observed, applied)
	}
	stateA, _ := readRevocationState(t, database, routes["a"], sessions["a"])
	stateB, _ := readRevocationState(t, database, routes["b"], sessions["b"])
	if stateA != "closed" || stateB != "starting" {
		t.Fatalf("selective session states = %s/%s", stateA, stateB)
	}
	if ok, closed, err := database.ApplyHostedPolicyRevocation(t.Context(), issuer, team, 6, true, nil, nil, now.Add(2*time.Second)); err != nil || ok || closed != 0 {
		t.Fatalf("revocation replay = %t/%d, %v", ok, closed, err)
	}
	if ok, closed, err := database.ApplyHostedPolicyRevocation(t.Context(), issuer, team, 7, false, nil, []string{"domain_revocation"}, now.Add(3*time.Second)); err != nil || !ok || closed != 1 {
		t.Fatalf("domain revocation = %t/%d, %v", ok, closed, err)
	}
	_, lifecycleA := readRevocationState(t, database, routes["a"], sessions["a"])
	stateB, lifecycleB := readRevocationState(t, database, routes["b"], sessions["b"])
	stateD, lifecycleD := readRevocationState(t, database, routes["d"], sessions["d"])
	if stateB != "closed" || stateD != "starting" || lifecycleA != "suspended" || lifecycleB != "suspended" || lifecycleD != "enabled" {
		t.Fatalf("domain revocation = %s/%s; routes %s/%s/%s", stateB, stateD, lifecycleA, lifecycleB, lifecycleD)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	updateDone, revocationDone := make(chan error, 1), make(chan error, 1)
	update.PolicyRevision, update.ExpectedMutationRevision, update.Target = 8, routeC.MutationRevision, "http://127.0.0.1:4000"
	workers.Go(func() {
		_, err := database.UpdateAuthorizedPublicURL(ctx, update, now.Add(4*time.Second))
		updateDone <- err
	})
	workers.Go(func() {
		ok, _, err := database.ApplyHostedPolicyRevocation(ctx, issuer, team, 8, true, nil, nil, now.Add(4*time.Second))
		if err == nil && !ok {
			err = errors.New("revision 8 was not applied")
		}
		revocationDone <- err
	})
	for _, done := range []<-chan error{updateDone, revocationDone} {
		if err := awaitIntegrationResult(t, ctx, done); err != nil {
			t.Fatalf("authorization/revocation race: %v", err)
		}
	}
	stateD, _ = readRevocationState(t, database, routes["d"], sessions["d"])
	if stateD != "closed" {
		t.Fatalf("team revocation left session %s", stateD)
	}
}

func readAuthorityRevisions(t *testing.T, database *Database, issuer, team string) (int64, int64) {
	t.Helper()
	var observed, applied int64
	if err := database.pool.QueryRow(t.Context(), `SELECT observed_policy_revision, applied_policy_revision FROM control.authority_revision_states WHERE issuer = $1 AND team_id = $2`, issuer, team).Scan(&observed, &applied); err != nil {
		t.Fatal(err)
	}
	return observed, applied
}

func readRevocationState(t *testing.T, database *Database, route PublicURL, session PublishRunSetup) (string, string) {
	t.Helper()
	var sessionState, publicURLState string
	if err := database.pool.QueryRow(t.Context(), `SELECT sessions.state, routes.lifecycle_state FROM control.publish_runs AS sessions JOIN control.public_urls AS routes ON routes.id = sessions.public_url_id WHERE routes.id = $1 AND sessions.id = $2`, route.ID, session.PublishRunID).Scan(&sessionState, &publicURLState); err != nil {
		t.Fatal(err)
	}
	return sessionState, publicURLState
}
