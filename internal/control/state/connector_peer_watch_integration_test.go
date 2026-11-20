package state

import (
	"bytes"
	"errors"
	"io/fs"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationConnectorPeerWatchCommittedChanges(t *testing.T) {
	d, now, _, leases := newConnectorPairPrerequisites(t)
	a := connectorPairFixtureInDatabase(t, d, now, leases, "watch-a")
	b := connectorPairFixtureInDatabase(t, d, now, leases, "watch-b")
	ctx := t.Context()
	reader, err := Open(ctx, d.pool.Config().ConnString(), testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)

	if err := reader.AuthorizeConnectorPeerWatch(ctx, a.run.ServiceID, a.run.RunID, a.run.RunNumber, a.run.Token, now); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		service, run, token string
		number              int64
	}{
		{a.run.ServiceID, a.run.RunID, b.run.Token, a.run.RunNumber},
		{b.run.ServiceID, a.run.RunID, a.run.Token, a.run.RunNumber},
		{a.run.ServiceID, a.run.RunID, a.run.Token, a.run.RunNumber + 1},
	} {
		if err := reader.AuthorizeConnectorPeerWatch(ctx, check.service, check.run, check.number, check.token, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatalf("watch accepted a mismatched run: %v", err)
		}
	}

	compare := func(bookmarks []ConnectorPeerWatchVersion, want ...ConnectorPeerWatchVersion) {
		t.Helper()
		got, err := reader.CompareConnectorPeerWatchVersions(ctx, bookmarks)
		if err != nil || len(got) != len(want) {
			t.Fatalf("compare = %v, %v; want %v", got, err, want)
		}
		for _, item := range want {
			if !slices.Contains(got, item) {
				t.Fatalf("compare = %v; missing %v", got, item)
			}
		}
	}
	seenA := ConnectorPeerWatchVersion{RunID: a.run.RunID, Revision: 0}
	seenB := ConnectorPeerWatchVersion{RunID: b.run.RunID, Revision: 0}
	compare([]ConnectorPeerWatchVersion{seenA, seenB})
	compare([]ConnectorPeerWatchVersion{{RunID: a.run.RunID, Revision: -1}}, seenA)
	pair := a.create(t)
	compare([]ConnectorPeerWatchVersion{seenA, seenB}, ConnectorPeerWatchVersion{a.run.RunID, 1})
	seenA.Revision = 1

	// hold a real pair mutation on A while B commits on a different connection.
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	if _, err := tx.Exec(ctx, `UPDATE control.connector_peer_pairs SET expires_at=expires_at-interval '1 second' WHERE id=$1`, pair.ID); err != nil {
		t.Fatal(err)
	}
	b.create(t)
	compare([]ConnectorPeerWatchVersion{seenA, seenB}, ConnectorPeerWatchVersion{b.run.RunID, 1})
	seenB.Revision = 1
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	compare([]ConnectorPeerWatchVersion{seenA, seenB}, ConnectorPeerWatchVersion{a.run.RunID, 2})
	seenA.Revision = 2

	rolledBack, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, rolledBack)
	if _, err := rolledBack.Exec(ctx, `UPDATE control.connector_peer_pairs SET expires_at=expires_at-interval '1 second' WHERE id=$1`, pair.ID); err != nil {
		t.Fatal(err)
	}
	if err := rolledBack.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	compare([]ConnectorPeerWatchVersion{seenA, seenB})

	for slot := range 2 {
		a.claim(t, pair, slot, now.Add(time.Second))
	}
	compare([]ConnectorPeerWatchVersion{seenA, seenB}, ConnectorPeerWatchVersion{a.run.RunID, 4})
	seenA.Revision = 4
	page, err := reader.ListConnectorPeerPairs(ctx, pair.ServiceID, pair.ServiceRunID, "", a.run.Token, now.Add(2*time.Second))
	if err != nil || len(page.Items) != 1 || page.Items[0].PairID != pair.ID || page.Items[0].Retired {
		t.Fatalf("authorized fetch after leg claims = %v, %v", page, err)
	}
	a.report(t, pair, pair.ExpiresAt.Add(-time.Second), now.Add(2*time.Second))
	if _, err := d.HeartbeatServiceRun(ctx, a.run.ServiceID, a.run.RunID, a.run.Token, now.Add(2*time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	compare([]ConnectorPeerWatchVersion{seenA, seenB})

	rebind := connectorRebindRequest(t, a, pair, "prepare", now.Add(3*time.Second))
	pending, err := d.RebindConnectorPeerPair(a.visitor, pair.ServiceID, pair.ID, rebind, rebind.Proof.RequestedAt)
	if err != nil || pending.Pending == nil {
		t.Fatal("prepare rebind:", err)
	}
	compare([]ConnectorPeerWatchVersion{seenA, seenB}, ConnectorPeerWatchVersion{a.run.RunID, 5})

	// this reader stays on revision 4, as if it disconnected before rebind.
	retire := connectorRetireRequest(t, a, pair, now.Add(4*time.Second))
	if _, err := d.RetireConnectorPeerPair(ctx, pair.ServiceID, pair.ID, retire, retire.Proof.RequestedAt); err != nil {
		t.Fatal(err)
	}
	compare([]ConnectorPeerWatchVersion{seenA, seenB}, ConnectorPeerWatchVersion{a.run.RunID, 6})
	page, err = reader.ListConnectorPeerPairs(ctx, pair.ServiceID, pair.ServiceRunID, "", a.run.Token, now.Add(5*time.Second))
	if err != nil || len(page.Items) != 1 || page.Items[0].PairID != pair.ID || !page.Items[0].Retired {
		t.Fatalf("authorized catch-up lost the retirement: %v, %v", page, err)
	}
	if err := d.CloseServiceRun(ctx, a.run.ServiceID, a.run.RunID, a.run.Token, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	missing := ConnectorPeerWatchVersion{RunID: mustOpaqueID(t, opaqueid.ServiceRunPrefix), Revision: -1}
	compare([]ConnectorPeerWatchVersion{seenA, seenB, missing}, ConnectorPeerWatchVersion{a.run.RunID, -1}, missing)
}

func watchMigrationFixture(t *testing.T, d *Database) (string, *goose.Provider) {
	t.Helper()
	pooledURL := d.pool.Config().ConnString()
	directURL, err := url.Parse(pooledURL)
	if err != nil {
		t.Fatal(err)
	}
	params := directURL.Query()
	params.Del("pool_max_conns")
	directURL.RawQuery = params.Encode()
	config, err := parseDirectConfig(directURL.String())
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*config)
	t.Cleanup(func() { _ = db.Close() })
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations,
		goose.WithTableName(versionTable), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	return directURL.String(), provider
}

func TestIntegrationConnectorPeerWatchMigrationPreservesExistingRun(t *testing.T) {
	f := newConnectorPairFixture(t)
	ctx := t.Context()
	pooledURL := f.d.pool.Config().ConnString()
	directURL, provider := watchMigrationFixture(t, f.d)
	if _, err := provider.DownTo(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if old, err := Open(ctx, pooledURL, testStorageKey, "", naming.ManagedURLModeGenerated); err == nil {
		old.Close()
		t.Fatal("control accepted the pre-watch schema without migrating")
	}
	// use the existing fixture's connection to write v1 rows without any
	// version triggers, then check the supported serving open after upgrade.
	pair := f.create(t)
	f.claim(t, pair, 0, f.now.Add(time.Second))
	before := connectorPairSavedAuthority(t, f.d, pair.ID)
	if err := Migrate(ctx, directURL); err != nil {
		t.Fatal(err)
	}
	reader, err := Open(ctx, pooledURL, testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	if after := connectorPairSavedAuthority(t, reader, pair.ID); !bytes.Equal(before, after) {
		t.Fatal("upgrade modified existing run or connector authority")
	}
	changes, err := reader.CompareConnectorPeerWatchVersions(ctx, []ConnectorPeerWatchVersion{{f.run.RunID, -1}})
	if err != nil || !slices.Equal(changes, []ConnectorPeerWatchVersion{{f.run.RunID, 0}}) {
		t.Fatalf("existing run did not request an initial snapshot: %v, %v", changes, err)
	}
	page, err := reader.ListConnectorPeerPairs(ctx, f.run.ServiceID, f.run.RunID, "", f.run.Token, f.now.Add(2*time.Second))
	if err != nil || len(page.Items) != 1 || page.Items[0].PairID != pair.ID {
		t.Fatalf("could not recover pre-upgrade inventory with the original run token: %v, %v", page, err)
	}
}
