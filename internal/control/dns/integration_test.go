package dns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationServiceDNSChallenges(t *testing.T) {
	database, sql, _ := challengeDatabase(t)
	for _, custom := range []bool{false, true} {
		name, domain, reference := "managed", "tunnels.example.test", ""
		if custom {
			name, domain = "custom", "custom.example.test"
			var err error
			reference, err = opaqueid.New(opaqueid.DNSAuthorityPrefix)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte("claim"))
			if err := controlstatedb.New(sql).CreateCustomDNSAuthority(t.Context(), controlstatedb.CreateCustomDNSAuthorityParams{
				AuthorityReference: reference, TeamID: "external_team", DomainID: "external_domain_custom", CanonicalDomain: domain,
				CreateIdempotencyKey: "claim", CreateRequestDigest: digest[:], CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := sql.Exec(t.Context(), `UPDATE control.dns_authorities SET state = 'ready', provider_zone_id = 'ZCLAIMED', nameservers = ARRAY['ns-1.example.test', 'ns-2.example.test'] WHERE authority_reference = $1`, reference); err != nil {
				t.Fatal(err)
			}
		}
		t.Run(name, func(t *testing.T) {
			seedHostedChallenge(t, database, sql, name, domain, reference)
			if !custom {
				challenge, err := database.GetDNSChallengeContextForSubject(t.Context(), serviceDNSSubject(challengeServiceID(name)), "authorization_"+name)
				if err != nil || challenge.CanonicalDomain != domain || challenge.DNSAuthorityReference != "" {
					t.Fatalf("managed service context = %#v, error %v", challenge, err)
				}
			}
			provider := &challengeProviderStub{zone: Zone{ID: "Z123", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}}
			manager, err := NewChallengeManager(database, provider, &challengeVerifierStub{verified: true}, Config{ManagedDomain: "tunnels.example.test", ManagedZoneID: "Z123"})
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.PresentSubject(t.Context(), serviceDNSSubject(challengeServiceID(name)), "authorization_"+name); err != nil {
				t.Fatal(err)
			}
			if provider.record.CustomZone != custom || provider.record.ZoneDomain != domain || provider.record.RecordName != "_acme-challenge.member."+domain {
				t.Fatalf("hosted challenge %#v", provider.record)
			}
			if _, err := sql.Exec(t.Context(), `UPDATE control.acme_authorizations SET state = 'presented' WHERE id = $1`, "authorization_"+name); err != nil {
				t.Fatal(err)
			}
			if valid, err := manager.VerifySubject(t.Context(), serviceDNSSubject(challengeServiceID(name)), "authorization_"+name); err != nil || !valid {
				t.Fatalf("verify = %v, %v", valid, err)
			}
			if custom {
				if _, err := sql.Exec(t.Context(), `UPDATE control.dns_authorities SET state = 'releasing' WHERE authority_reference = $1`, reference); err != nil {
					t.Fatal(err)
				}
				if valid, err := manager.VerifySubject(t.Context(), serviceDNSSubject(challengeServiceID(name)), "authorization_"+name); err == nil || valid {
					t.Fatalf("releasing authority verified new work: %v, %v", valid, err)
				}
			}
			if _, err := sql.Exec(t.Context(), `UPDATE control.acme_authorizations SET state = 'cleaning' WHERE id = $1`, "authorization_"+name); err != nil {
				t.Fatal(err)
			}
			if err := manager.CleanupSubject(t.Context(), serviceDNSSubject(challengeServiceID(name)), "authorization_"+name); err != nil {
				t.Fatal(err)
			}
			if len(provider.record.DesiredOwnedValues) != 0 || len(provider.record.PreviouslyOwnedValues) != 1 {
				t.Fatalf("cleanup %#v", provider.record)
			}
			calls := provider.calls
			if err := manager.CleanupSubject(t.Context(), serviceDNSSubject(challengeServiceID("wrong")), "authorization_"+name); !errors.Is(err, controlstate.ErrDNSChallengeNotFound) {
				t.Fatalf("wrong service identity = %v", err)
			}
			if _, err := sql.Exec(t.Context(), `UPDATE control.domains SET canonical_domain = $2 WHERE id = $1`, challengeDomainID(name, domain), "outside."+name+".example.test"); err != nil {
				t.Fatal(err)
			}
			if err := manager.CleanupSubject(t.Context(), serviceDNSSubject(challengeServiceID(name)), "authorization_"+name); err == nil || provider.calls != calls {
				t.Fatalf("out-of-scope service cleanup = %v, calls %d", err, provider.calls)
			}
		})
	}
	var domains int
	if err := sql.QueryRow(t.Context(), `SELECT count(*) FROM control.domains`).Scan(&domains); err != nil || domains != 2 {
		t.Fatalf("fixture domains = %d, error %v", domains, err)
	}
}

func TestIntegrationDNSChallengeSerialization(t *testing.T) {
	database, sql, databaseURL := challengeDatabase(t)
	otherDatabase, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherDatabase.Close)
	for _, name := range []string{"old", "new"} {
		seedHostedChallenge(t, database, sql, name, "tunnels.example.test", "")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	const recordName = "_acme-challenge.member.tunnels.example.test"
	providerStarted, releaseProvider := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseProvider) }) }
	defer release()
	var reconciliations atomic.Int32
	provider := &challengeProviderStub{reconcile: func(ctx context.Context, _ ChallengeRecord) (Zone, error) {
		if reconciliations.Add(1) == 1 {
			close(providerStarted)
			select {
			case <-releaseProvider:
			case <-ctx.Done():
				return Zone{}, ctx.Err()
			}
		}
		return Zone{}, nil
	}}
	manager, err := NewChallengeManager(database, provider, &challengeVerifierStub{}, Config{ManagedDomain: "tunnels.example.test", ManagedZoneID: "Z123"})
	if err != nil {
		t.Fatal(err)
	}
	otherManager, err := NewChallengeManager(otherDatabase, provider, &challengeVerifierStub{}, Config{ManagedDomain: "tunnels.example.test", ManagedZoneID: "Z123"})
	if err != nil {
		t.Fatal(err)
	}
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	var workers sync.WaitGroup
	t.Cleanup(func() { release(); cancel(); workers.Wait() })
	workers.Go(func() {
		firstDone <- manager.PresentSubject(ctx, serviceDNSSubject(challengeServiceID("new")), "authorization_new")
	})
	select {
	case <-providerStarted:
	case err := <-firstDone:
		t.Fatalf("first presentation failed before reaching the provider: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := sql.Exec(ctx, `UPDATE control.acme_authorizations SET state = 'cleaning' WHERE id = 'authorization_old'`); err != nil {
		t.Fatal(err)
	}
	workers.Go(func() {
		secondDone <- otherManager.CleanupSubject(ctx, serviceDNSSubject(challengeServiceID("old")), "authorization_old")
	})
	// observe PostgreSQL contention rather than assuming a goroutine was scheduled.
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		if err := sql.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND database = (SELECT oid FROM pg_database WHERE datname = current_database()))`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-secondDone:
			t.Fatalf("cleanup bypassed the durable lock: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}
	if err := otherDatabase.WithDNSRecordLock(ctx, "_acme-challenge.unrelated.example.test", func() error { return otherDatabase.Health(ctx) }); err != nil {
		t.Fatalf("unrelated record or pool read was blocked: %v", err)
	}
	// this presentation did not exist in either caller's pre-lock snapshot.
	seedHostedChallenge(t, database, sql, "third", "tunnels.example.test", "")
	release()
	for _, done := range []chan error{firstDone, secondDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	provider.mu.Lock()
	got, calls := provider.record, provider.calls
	provider.mu.Unlock()
	newDigest := sha256.Sum256([]byte("new"))
	thirdDigest := sha256.Sum256([]byte("third"))
	want := []string{challengeTXTValue(newDigest), challengeTXTValue(thirdDigest)}
	slices.Sort(want)
	if calls != 2 || !slices.Equal(got.DesiredOwnedValues, want) {
		t.Fatalf("post-lock challenge record = %#v after %d reconciliations, want active values %q", got, calls, want)
	}
	for _, canceled := range []bool{false, true} {
		lockCtx, cancelLock := context.WithCancel(ctx)
		failure := errors.New("provider failure")
		err := database.WithDNSRecordLock(lockCtx, recordName, func() error {
			if canceled {
				cancelLock()
				return lockCtx.Err()
			}
			return failure
		})
		cancelLock()
		if canceled {
			failure = context.Canceled
		}
		if !errors.Is(err, failure) {
			t.Fatalf("lock failure = %v", err)
		}
		if err := otherDatabase.WithDNSRecordLock(ctx, recordName, func() error { return otherDatabase.Health(ctx) }); err != nil {
			t.Fatalf("lock leaked after callback failure: %v", err)
		}
	}
}

func challengeDatabase(t *testing.T) (*controlstate.Database, *pgx.Conn, string) {
	t.Helper()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "dns")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	sql, err := pgx.Connect(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sql.Close(context.Background()) })
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("pool_max_conns", "1")
	parsed.RawQuery = query.Encode()
	database, err := controlstate.Open(t.Context(), parsed.String(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	return database, sql, parsed.String()
}

func seedHostedChallenge(t *testing.T, database *controlstate.Database, sql *pgx.Conn, name, domain, reference string) {
	t.Helper()
	now := time.Now().UTC()
	digest := sha256.Sum256([]byte(name))
	base := "member." + domain
	domainID := challengeDomainID(name, domain)
	serviceID := challengeServiceID(name)
	runID := serviceDNSSubject(serviceID).RunID
	domainKind := "managed"
	var teamID, authorityReference any
	if reference != "" {
		domainKind, teamID, authorityReference = "custom", "external_team", reference
	}
	account, err := database.EnsureACMEAccount(t.Context(), "https://acme.example.test/directory", "operator@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{base, "*." + base}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrDigest := sha256.Sum256(csr)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO control.identities (id, kind, display_name, created_at, updated_at) VALUES ('external_identity', 'authority', 'External identity', $1, $1) ON CONFLICT DO NOTHING`, []any{now}},
		{`INSERT INTO control.managed_label_reservations (label, created_at) VALUES ('external', $1) ON CONFLICT DO NOTHING`, []any{now}},
		{`INSERT INTO control.teams (id, kind, display_name, managed_label, created_by_identity_id, created_at, updated_at) VALUES ('external_team', 'organization', 'external', 'external', 'external_identity', $1, $1) ON CONFLICT DO NOTHING`, []any{now}},
		{`INSERT INTO control.domains (id, kind, team_id, canonical_domain, dns_authority_reference, state, authority_revision, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, 'ready', 1, $6, $6) ON CONFLICT DO NOTHING`, []any{domainID, domainKind, teamID, domain, authorityReference, now}},
		{`INSERT INTO control.publisher_identities (id, team_id, name, kind, created_by_identity_id, ownership, created_at) VALUES ('dns_publisher', 'external_team', 'dns', 'automation', 'external_identity', 'team', $1) ON CONFLICT DO NOTHING`, []any{now}},
		{`INSERT INTO control.publisher_identity_keys (id, publisher_identity_id, public_key, revision, created_at) VALUES ('dns_publisher_key', 'dns_publisher', $1, 1, $2) ON CONFLICT DO NOTHING`, []any{digest[:], now}},
		{`INSERT INTO control.services (id, team_id, name, protocol, domain_id, certificate_hostname, certificate_scope, created_by_identity_id, idempotency_key, request_digest, created_at, updated_at) VALUES ($1, 'external_team', $2, 'http', $3, $4, $5, 'external_identity', $1, $6, $7, $7)`, []any{serviceID, name, domainID, name + "." + base, base, digest[:], now}},
		{`INSERT INTO control.publisher_grants (id, publisher_identity_id, team_id, created_by_identity_id, kind, service_id, protocols, created_at) VALUES ($1, 'dns_publisher', 'external_team', 'external_identity', 'service', $2, ARRAY['http'], $3)`, []any{"grant_" + name, serviceID, now}},
		// serving authority uses the existing publisher bound, not the shorter preparation deadline.
		{`INSERT INTO control.service_runs (id, service_id, protocol, team_id, run_number, publisher_identity_id, publisher_grant_id, publisher_key_id, idempotency_key, request_digest, preparation_expires_at, assignment_seed_ciphertext, assignment_seed_storage_key_id, traffic_limits, certificate_cache_key, certificate_scope, certificate_identifiers, certificate_domain_id, certificate_hostname, certificate_namespace, created_at, publisher_expires_at, serving_observed_at, serving_until, state) VALUES ($1, $2, 'http', 'external_team', 1, 'dns_publisher', $3, 'dns_publisher_key', $1, $4, $5, $4, 'test-key', '{}', $6, $6, $7, $8, $9, $6, $10, $11, $10, $11, 'prepared')`, []any{runID, serviceID, "grant_" + name, digest[:], now.Add(time.Minute), base, []string{base, "*." + base}, domainID, name + "." + base, now, now.Add(time.Hour)}},
		{`INSERT INTO control.acme_orders (id, account_id, service_run_id, service_id, service_run_number, idempotency_key, request_digest, certificate_cache_key, certificate_scope, certificate_domain_id, certificate_identifiers, challenge_method, csr_der, csr_digest, state, available_at, created_at, updated_at) VALUES ($1, $2, $3, $4, 1, $1, $5, $6, $6, $7, $8, 'dns-01', $9, $10, 'authorizing', $11, $11, $11)`, []any{"order_" + name, account.ID, runID, serviceID, digest[:], base, domainID, []string{base, "*." + base}, csr, csrDigest[:], now}},
		{`INSERT INTO control.acme_authorizations (id, order_id, identifier, authorization_url, challenge_type, challenge_url, challenge_token, challenge_digest, presentation_reference, state, available_at, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, 'dns-01', $5, 'token', $6, $1, 'presenting', $7, $8, $7, $7)`, []any{"authorization_" + name, "order_" + name, "*." + base, "https://acme.example.test/authz/" + name, "https://acme.example.test/challenge/" + name, digest[:], now, now.Add(time.Hour)}},
	} {
		if _, err := sql.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func challengeServiceID(name string) string {
	digest := sha256.Sum256([]byte(name))
	return "svc_" + hex.EncodeToString(digest[:])[:22]
}

func challengeDomainID(name, domain string) string {
	if domain == "tunnels.example.test" {
		return "external_domain_managed"
	}
	return "external_domain_" + name
}
