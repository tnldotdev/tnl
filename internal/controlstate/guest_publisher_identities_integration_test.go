package controlstate

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

func TestIntegrationGuestPublisherMigrationFollowsLiveIP(t *testing.T) {
	ctx := t.Context()
	url := newDisposableControlStateDatabaseURL(t, "guest_publisher_upgrade")
	config, err := parseDirectConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	direct := stdlib.OpenDB(*config)
	t.Cleanup(func() { _ = direct.Close() })
	if err := ensureMigrationLock(ctx, direct); err != nil {
		t.Fatal(err)
	}
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, direct, migrations,
		goose.WithTableName(versionTable), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	for _, version := range []int64{32, 33} {
		if _, err := provider.UpTo(ctx, version); err != nil {
			t.Fatalf("migrate to %d: %v", version, err)
		}
		current, err := readSchemaVersion(ctx, pool)
		if err != nil || current != version {
			t.Fatalf("schema version = %d, %v; want %d", current, err, version)
		}
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('control.guest_publisher_identities') IS NOT NULL`).Scan(&exists); err != nil || exists {
			t.Fatalf("guest identity table at version %d = %t, %v", version, exists, err)
		}
	}
	if err := checkSchemaVersion(ctx, pool); err == nil {
		t.Fatal("guest publisher runtime accepted schema 33 without its trial link")
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("migrate from 33 to 34: %v", err)
	}
	current, err := readSchemaVersion(ctx, pool)
	if err != nil || current != 34 {
		t.Fatalf("final schema version = %d, %v", current, err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('control.guest_publisher_identities') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatalf("guest identity table at version 34 = %t, %v", exists, err)
	}
	if err := checkSchemaVersion(ctx, pool); err != nil {
		t.Fatalf("guest publisher runtime rejected schema 34: %v", err)
	}
}

func TestIntegrationGuestPublisherStaysInsideItsTrial(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "guest_publisher")
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	domainID, err := database.CreateGuestTrial(t.Context(), guest, "example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := database.RegisterGuestPublisherIdentity(t.Context(), guest.ID, public, now)
	if err != nil || identity.GuestID != guest.ID || identity.Scope.TeamID != guest.TeamID ||
		identity.Scope.DomainID != domainID || identity.Scope.Namespace != guest.NamespaceLabel+".example.test" {
		t.Fatalf("guest publisher identity = %+v, %v", identity, err)
	}
	for _, test := range []struct {
		ip      string
		allowed bool
	}{{"192.0.2.7", true}, {"192.0.2.8", false}} {
		matched, err := database.GuestPublisherSourceMatches(t.Context(), guest.ID, netip.MustParseAddr(test.ip))
		if err != nil || matched != test.allowed {
			t.Fatalf("source %s = %t, %v", test.ip, matched, err)
		}
	}
	const audience = "https://control.example/v1/publisher/token"
	assertion, err := publisheridentity.Sign(identity.ID, identity.KeyID, audience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := database.ExchangePublisherAssertion(t.Context(), identity.ID, identity.GrantID, audience, assertion, now)
	if err != nil || access.GuestID != guest.ID || access.Scope != identity.Scope {
		t.Fatalf("guest access = %+v, %v", access, err)
	}
	authenticated, err := database.AuthenticatePublisherAccess(t.Context(), access.Token, now)
	if err != nil || authenticated.GuestID != guest.ID {
		t.Fatalf("guest token scope = %+v, %v", authenticated, err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns = $2 WHERE id = $1`,
		guest.ID, int64(GuestReadyAllowance)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AuthenticatePublisherAccess(t.Context(), access.Token, now.Add(time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("spent trial retained publisher access: %v", err)
	}
	other, err := publisheridentity.Sign(identity.ID, identity.KeyID, audience, private, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExchangePublisherAssertion(t.Context(), identity.ID, identity.GrantID, audience, other, now.Add(time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("spent trial exchanged a new token: %v", err)
	}
}
