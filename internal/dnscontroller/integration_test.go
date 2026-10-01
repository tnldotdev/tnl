package dnscontroller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/testutil"
)

const hostedManagedAuthorityReference = "dns_authority_0123456789abcdef0123456789abcdef"

func TestIntegrationHostedDNSChallengesWithoutBuiltinDomains(t *testing.T) {
	database, sql, _ := challengeDatabase(t)
	for _, claimed := range []bool{false, true} {
		name, domain, reference := "managed_opaque_reference", "tunnels.example.test", hostedManagedAuthorityReference
		if claimed {
			name, domain = "claimed", "claimed.example.test"
			authority, err := database.CreateDNSAuthority(t.Context(), controlstate.CreateDNSAuthorityRequest{
				TeamID: "external_team", DomainID: "external_domain_claimed", CanonicalDomain: domain,
				IdempotencyKey: "claim", RequestDigest: sha256.Sum256([]byte("claim")),
			}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			reference = authority.Reference
			if _, err := sql.Exec(t.Context(), `UPDATE control.dns_authorities SET state = 'ready', provider_zone_id = 'ZCLAIMED', nameservers = ARRAY['ns-1.example.test', 'ns-2.example.test'] WHERE authority_reference = $1`, reference); err != nil {
				t.Fatal(err)
			}
		}
		t.Run(name, func(t *testing.T) {
			seedHostedChallenge(t, database, sql, name, domain, reference)
			if !claimed {
				challenge, err := database.GetDNSChallengeContext(t.Context(), "public_url_"+name, "authorization_"+name)
				if err != nil || challenge.CanonicalDomain != "" || challenge.DNSAuthorityReference != reference {
					t.Fatalf("hosted managed context = %#v, error %v", challenge, err)
				}
				if _, err := database.GetDNSAuthority(t.Context(), reference); !errors.Is(err, controlstate.ErrDNSAuthorityNotFound) {
					t.Fatalf("opaque hosted reference must not require a control authority row: %v", err)
				}
			}
			provider := &challengeProviderStub{zone: Zone{ID: "Z123", Nameservers: []string{"ns-1.example.test", "ns-2.example.test"}}}
			manager, err := NewChallengeManager(database, provider, &challengeVerifierStub{verified: true}, Config{ManagedDomain: "tunnels.example.test", ManagedZoneID: "Z123"})
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Present(t.Context(), "public_url_"+name, "authorization_"+name); err != nil {
				t.Fatal(err)
			}
			if provider.record.ClaimedZone != claimed || provider.record.ZoneDomain != domain || provider.record.RecordName != "_acme-challenge.member."+domain {
				t.Fatalf("hosted challenge %#v", provider.record)
			}
			if _, err := sql.Exec(t.Context(), `UPDATE control.acme_authorizations SET state = 'presented' WHERE id = $1`, "authorization_"+name); err != nil {
				t.Fatal(err)
			}
			if valid, err := manager.Verify(t.Context(), "public_url_"+name, "authorization_"+name); err != nil || !valid {
				t.Fatalf("verify = %v, %v", valid, err)
			}
			if claimed {
				if _, err := sql.Exec(t.Context(), `UPDATE control.dns_authorities SET state = 'releasing' WHERE authority_reference = $1`, reference); err != nil {
					t.Fatal(err)
				}
				if valid, err := manager.Verify(t.Context(), "public_url_"+name, "authorization_"+name); err == nil || valid {
					t.Fatalf("releasing authority verified new work: %v, %v", valid, err)
				}
			}
			if _, err := sql.Exec(t.Context(), `UPDATE control.acme_authorizations SET state = 'cleaning' WHERE id = $1`, "authorization_"+name); err != nil {
				t.Fatal(err)
			}
			if err := manager.Cleanup(t.Context(), "public_url_"+name, "authorization_"+name); err != nil {
				t.Fatal(err)
			}
			if len(provider.record.DesiredOwnedValues) != 0 || len(provider.record.PreviouslyOwnedValues) != 1 {
				t.Fatalf("cleanup %#v", provider.record)
			}
			calls := provider.calls
			if err := manager.Cleanup(t.Context(), "wrong_route", "authorization_"+name); !errors.Is(err, controlstate.ErrDNSChallengeNotFound) {
				t.Fatalf("wrong route identity = %v", err)
			}
			if _, err := sql.Exec(t.Context(), `UPDATE control.public_urls SET canonical_hostname = $2 WHERE id = $1`, "public_url_"+name, "outside."+name+".example.test"); err != nil {
				t.Fatal(err)
			}
			if err := manager.Cleanup(t.Context(), "public_url_"+name, "authorization_"+name); err == nil || provider.calls != calls {
				t.Fatalf("out-of-scope route cleanup = %v, calls %d", err, provider.calls)
			}
		})
	}
	var domains int
	if err := sql.QueryRow(t.Context(), `SELECT count(*) FROM control.domains`).Scan(&domains); err != nil || domains != 0 {
		t.Fatalf("builtin domains = %d, error %v", domains, err)
	}
}

func TestIntegrationDNSChallengeSerialization(t *testing.T) {
	database, sql, databaseURL := challengeDatabase(t)
	otherDatabase, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherDatabase.Close)
	for _, name := range []string{"old", "new"} {
		seedHostedChallenge(t, database, sql, name, "tunnels.example.test", hostedManagedAuthorityReference)
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
	workers.Go(func() { firstDone <- manager.Present(ctx, "public_url_new", "authorization_new") })
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
	workers.Go(func() { secondDone <- otherManager.Cleanup(ctx, "public_url_old", "authorization_old") })
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
	if err := otherDatabase.WithDNSChallengeLock(ctx, "_acme-challenge.unrelated.example.test", func() error { return otherDatabase.Health(ctx) }); err != nil {
		t.Fatalf("unrelated record or pool read was blocked: %v", err)
	}
	// this presentation did not exist in either caller's pre-lock snapshot.
	seedHostedChallenge(t, database, sql, "third", "tunnels.example.test", hostedManagedAuthorityReference)
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
		err := database.WithDNSChallengeLock(lockCtx, recordName, func() error {
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
		if err := otherDatabase.WithDNSChallengeLock(ctx, recordName, func() error { return otherDatabase.Health(ctx) }); err != nil {
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
	database, err := controlstate.Open(t.Context(), parsed.String(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
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
	domainID := "external_domain_" + name
	if domain == "tunnels.example.test" {
		domainID = "external_domain_managed"
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
		{`INSERT INTO control.public_urls (id, team_id, domain_id, membership_id, created_by_identity_id, idempotency_key, request_digest, canonical_hostname, target, public_url_scope, policy_revision, ip_policy, lifecycle_state, dns_authority_reference, dns_state, created_at, updated_at) VALUES ($1, 'external_team', $2, 'external_membership', 'external_identity', $1, $3, $4, 'http://127.0.0.1:3000', 'member', 1, 'allow_all', 'enabled', $5, 'published', $6, $6)`, []any{"public_url_" + name, domainID, digest[:], name + "." + base, reference, now}},
		{`INSERT INTO control.publish_runs (id, public_url_id, team_id, acting_identity_id, publish_run_number, idempotency_key, request_digest, publish_run_token_id, publish_run_token_digest, policy_revision, certificate_cache_key, certificate_scope, certificate_identifiers, certificate_challenge, state, created_at, last_heartbeat_at, publisher_expires_at) VALUES ($1, $2, 'external_team', 'external_identity', 1, $1, $3, $1, $3, 1, $4, $4, $5, 'dns-01', 'starting', $6, $6, $7)`, []any{"session_" + name, "public_url_" + name, digest[:], base, []string{base, "*." + base}, now, now.Add(time.Hour)}},
		{`INSERT INTO control.acme_orders (id, account_id, publish_run_id, public_url_id, publish_run_number, idempotency_key, request_digest, certificate_cache_key, certificate_scope, certificate_identifiers, challenge_method, csr_der, csr_digest, state, available_at, created_at, updated_at) VALUES ($1, $2, $3, $4, 1, $1, $5, $6, $6, $7, 'dns-01', $8, $9, 'authorizing', $10, $10, $10)`, []any{"order_" + name, account.ID, "session_" + name, "public_url_" + name, digest[:], base, []string{base, "*." + base}, csr, csrDigest[:], now}},
		{`INSERT INTO control.acme_authorizations (id, order_id, identifier, authorization_url, challenge_type, challenge_url, challenge_token, challenge_digest, presentation_reference, state, available_at, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, 'dns-01', $5, 'token', $6, $1, 'presenting', $7, $8, $7, $7)`, []any{"authorization_" + name, "order_" + name, "*." + base, "https://acme.example.test/authz/" + name, "https://acme.example.test/challenge/" + name, digest[:], now, now.Add(time.Hour)}},
	} {
		if _, err := sql.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}
