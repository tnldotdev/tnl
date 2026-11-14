package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func publicURLConnectorPairFixture(t *testing.T) (publishRunFixture, connectorPairFixture, PublisherIdentity) {
	t.Helper()
	d, now, _, leases := newConnectorPairPrerequisites(t)
	creation := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, creation, now)
	publisher, publisherKey := reviewPublisher(t, d, url, creation.ActingIdentityID, now)
	request := reviewRunRequest(t, d, publisher, publisherKey, url, "public-connector")
	setup, err := d.CreatePublishRun(t.Context(), request, now, 2*time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	public := publishRunFixture{database: d, now: now, request: request, setup: setup, leases: leases}
	readyTestSession(t, public)
	session := newOIDCSession(t, d, now)
	principal := ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x46}, ed25519.SeedSize))
	device, err := d.EnrollVisitorDevice(t.Context(), principal.IdentityID, key.Public().(ed25519.PublicKey), now)
	if err != nil {
		t.Fatal(err)
	}
	native := connectorPairFixture{d: d, now: now, visitor: WithControlPrincipal(t.Context(), principal), key: key, leases: leases}
	native.request = ConnectorPeerPairRequest{PublicURLID: url.ID, PublishRunID: setup.PublishRunID, PublishRunNumber: int64(setup.PublishRunNumber),
		PublisherIdentityID: publisher.ID, IdempotencyKey: "public-owner", Action: "create", RequestedAt: now,
		Subject: VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: principal.IdentityID, DeviceID: device.ID},
		Source:  DeviceTokenSource{DeviceID: device.ID}}
	for slot, assignment := range setup.PublisherConnections {
		native.request.ExpectedRelays[slot] = ConnectorPeerPairRelay{PublisherConnectionID: assignment.PublisherConnectionID,
			AssignmentRevision: int64(assignment.ConnectionAssignmentRevision), RelayLease: leases[assignment.RelayServiceID].RelayLeaseIdentity,
			RelayAddress: assignment.RelayAddress, TLSServerName: assignment.TLSServerName}
	}
	native.sign(t, &native.request)
	return public, native, publisher
}

func TestIntegrationPublicURLConnectorPairUsesExistingOwnerReplayAndRenewal(t *testing.T) {
	public, native, publisher := publicURLConnectorPairFixture(t)
	pair := native.create(t)
	if pair.PublicURLID != public.request.PublicURLID || pair.PublishRunID != public.setup.PublishRunID ||
		pair.PublishRunNumber != int64(public.setup.PublishRunNumber) || pair.PublisherIdentityID != publisher.ID ||
		pair.ServiceID != "" || pair.ServiceRunID != "" || pair.RunNumber != 0 || pair.TrustRevision < 1 ||
		pair.ExpiresAt.After(public.setup.ExpiresAt) {
		t.Fatal("authorized public URL pair lost its exact publication or deadline")
	}
	replay := native.create(t)
	if replay.ID != pair.ID || replay.DeliveryID != pair.DeliveryID || replay.DeliveryGeneration != pair.DeliveryGeneration ||
		replay.Key != pair.Key || replay.SessionKey != pair.SessionKey || replay.TrustRevision != pair.TrustRevision {
		t.Fatal("public URL create replay replaced an existing owner")
	}
	renewal := native.request
	renewal.Action, renewal.PreviousPairID, renewal.PreviousGeneration = "renew", pair.ID, pair.DeliveryGeneration
	renewal.RequestedAt = native.now.Add(time.Second)
	native.sign(t, &renewal)
	renewed, err := native.d.RenewConnectorPeerPair(native.visitor, testVisitorIssuer, renewal, renewal.RequestedAt)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ID != pair.ID || renewed.Key != pair.Key || renewed.SessionKey != pair.SessionKey || renewed.DeliveryGeneration != pair.DeliveryGeneration ||
		renewed.Metadata.Endpoint == nil || !renewed.Metadata.Endpoint.Public || renewed.Metadata.Endpoint.Port < 1024 ||
		renewed.VisitorPermission.Permission.Scope != (visitorscope.Scope{Kind: visitorscope.PublicURL, ID: pair.PublicURLID}) ||
		renewed.VisitorPermission.ServiceTrustRevision != 0 || renewed.VisitorPermission.Permission.Port != uint16(renewed.Metadata.Endpoint.Port) {
		t.Fatal("renewal changed owner identity or substituted a service permission")
	}
	stale := native.request
	stale.IdempotencyKey = "other-owner"
	native.sign(t, &stale)
	other, err := native.d.PrepareConnectorPeerPair(native.visitor, stale, native.now)
	if err != nil || other.ID == pair.ID {
		t.Fatal("independent public URL owners shared delivery state", err)
	}
	var savedKey string
	if err := native.d.pool.QueryRow(t.Context(), `SELECT publisher_key_id FROM control.publish_runs WHERE id=$1`, pair.PublishRunID).Scan(&savedKey); err != nil || savedKey != publisher.KeyID {
		t.Fatal("publish run did not retain its original publisher key", err)
	}
}

func TestIntegrationPublicURLConnectorPairRejectsStaleRunAndPublisherFacts(t *testing.T) {
	for _, test := range []struct {
		name  string
		query string
		want  error
	}{
		{"unready run", `UPDATE control.publish_runs SET state='starting',ready_at=NULL WHERE id=$1`, ErrServiceAccess},
		{"expired certificate", `UPDATE control.publish_runs SET certificate_installed_at=created_at,certificate_not_after=created_at+interval '1 microsecond' WHERE id=$1`, ErrServiceAccess},
		{"unapproved hostname", `UPDATE control.public_urls SET canonical_hostname='unapproved.example.test' WHERE id=(SELECT public_url_id FROM control.publish_runs WHERE id=$1)`, ErrServiceAccess},
		{"missing publisher key", `UPDATE control.publish_runs SET publisher_key_id=NULL WHERE id=$1`, ErrServiceAccess},
		{"retired publisher key", `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=(SELECT publisher_key_id FROM control.publish_runs WHERE id=$1)`, ErrServiceAccess},
		{"revoked publisher grant", `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=(SELECT publisher_grant_id FROM control.publish_runs WHERE id=$1)`, ErrPublisherIdentity},
	} {
		t.Run(test.name, func(t *testing.T) {
			public, native, _ := publicURLConnectorPairFixture(t)
			// keep the old signed request current while the retained authority
			// fact changes. no failed preparation may leave delivery secrets.
			args := []any{public.setup.PublishRunID}
			if test.name == "retired publisher key" || test.name == "revoked publisher grant" {
				args = append(args, native.now)
			}
			if _, err := native.d.pool.Exec(t.Context(), test.query, args...); err != nil {
				t.Fatal(err)
			}
			if pair, err := native.d.PrepareConnectorPeerPair(native.visitor, native.request, native.now.Add(time.Second)); !errors.Is(err, test.want) || pair.ID != "" || pair.Key != "" {
				t.Fatal("stale run or publisher facts authorized public URL delivery", err)
			}
			var count int
			if err := native.d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.connector_peer_pairs WHERE publish_run_id=$1`, public.setup.PublishRunID).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed public URL authority committed a pair", err)
			}
		})
	}
}

func TestIntegrationPublicURLConnectorPairMetadataChangesRequireReplacement(t *testing.T) {
	public, native, _ := publicURLConnectorPairFixture(t)
	pair := native.create(t)
	renewal := native.request
	renewal.Action, renewal.PreviousPairID, renewal.PreviousGeneration = "renew", pair.ID, pair.DeliveryGeneration
	renewal.RequestedAt = native.now.Add(time.Second)
	native.sign(t, &renewal)
	// ordinary visitor policy changes do not renumber the metadata snapshot.
	if _, err := native.d.pool.Exec(t.Context(), `UPDATE control.public_urls SET access_mode='anonymous' WHERE id=$1`, pair.PublicURLID); err != nil {
		t.Fatal(err)
	}
	renewed, err := native.d.RenewConnectorPeerPair(native.visitor, testVisitorIssuer, renewal, renewal.RequestedAt)
	if err != nil || renewed.TrustRevision != pair.TrustRevision {
		t.Fatal("visitor policy changed immutable endpoint trust", err)
	}
	if _, err := native.d.pool.Exec(t.Context(), `UPDATE control.public_urls SET publisher_pool=NOT publisher_pool WHERE id=$1`, pair.PublicURLID); err != nil {
		t.Fatal(err)
	}
	renewal.RequestedAt = native.now.Add(2 * time.Second)
	native.sign(t, &renewal)
	if rejected, err := native.d.RenewConnectorPeerPair(native.visitor, testVisitorIssuer, renewal, renewal.RequestedAt); !errors.Is(err, ErrServiceAccess) || rejected.ID != "" {
		t.Fatal("old metadata renewed an existing public URL pair", err)
	}
	saved, err := controlstatedb.New(native.d.pool).LockConnectorPeerPairForLegClaim(t.Context(), pair.ID)
	if err != nil || saved.TrustRevision != pair.TrustRevision || saved.PublicURLID != public.request.PublicURLID {
		t.Fatal("failed metadata renewal changed the retained owner", err)
	}
	replacement := native.request
	replacement.Action, replacement.PreviousPairID, replacement.PreviousGeneration = "replace", pair.ID, pair.DeliveryGeneration
	replacement.RequestedAt = renewal.RequestedAt
	native.sign(t, &replacement)
	replaced, err := native.d.PrepareConnectorPeerPair(native.visitor, replacement, replacement.RequestedAt)
	if err != nil || replaced.ID == pair.ID || replaced.TrustRevision <= pair.TrustRevision || replaced.PublicURLID != pair.PublicURLID ||
		replaced.PublishRunID != pair.PublishRunID || replaced.PublishRunNumber != pair.PublishRunNumber || replaced.SessionKey == pair.SessionKey {
		t.Fatal("public URL replacement lost its owner scope or metadata fence", err)
	}
}

func TestIntegrationPublicURLConnectorPairPinsPreviewSelection(t *testing.T) {
	public, native, _ := publicURLConnectorPairFixture(t)
	selected, err := native.d.CreatePreview(t.Context(), public.request.TeamID, public.request.ActingIdentityID, "selected", native.now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := native.d.CreatePreview(t.Context(), public.request.TeamID, public.request.ActingIdentityID, "other", native.now)
	if err != nil {
		t.Fatal(err)
	}
	source := native.request.Source.(DeviceTokenSource)
	source.PreviewID = selected.ID
	native.request.Source = source
	native.sign(t, &native.request)
	pair := native.create(t)
	saved, err := controlstatedb.New(native.d.pool).LockConnectorPeerPairForLegClaim(t.Context(), pair.ID)
	if err != nil || !saved.PreviewID.Valid || saved.PreviewID.String != selected.ID {
		t.Fatal("public URL pair did not capture the selected preview", err)
	}
	for _, preview := range []string{"", other.ID} {
		changed := native.request
		source.PreviewID = preview
		changed.Source = source
		native.sign(t, &changed)
		if got, err := native.d.PrepareConnectorPeerPair(native.visitor, changed, native.now); !errors.Is(err, ErrServiceConflict) || got.ID != "" || got.Key != "" {
			t.Fatal("create replay changed the retained preview", err)
		}
		changed.Action, changed.PreviousPairID, changed.PreviousGeneration = "renew", pair.ID, pair.DeliveryGeneration
		changed.RequestedAt = native.now.Add(time.Second)
		native.sign(t, &changed)
		if got, err := native.d.RenewConnectorPeerPair(native.visitor, testVisitorIssuer, changed, changed.RequestedAt); !errors.Is(err, ErrServiceConflict) || got.ID != "" || got.Key != "" {
			t.Fatal("renewal changed the retained preview", err)
		}
	}
}

func TestIntegrationPublicURLConnectorPairRejectsSubstitutedPublication(t *testing.T) {
	public, native, _ := publicURLConnectorPairFixture(t)
	for name, edit := range map[string]func(*ConnectorPeerPairRequest){
		"publish run": func(r *ConnectorPeerPairRequest) { r.PublishRunID = "pr_1234567890123456789012" },
		"run number":  func(r *ConnectorPeerPairRequest) { r.PublishRunNumber++ },
		"publisher":   func(r *ConnectorPeerPairRequest) { r.PublisherIdentityID = "pub_1234567890123456789012" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := native.request
			edit(&changed)
			native.sign(t, &changed)
			if got, err := native.d.PrepareConnectorPeerPair(native.visitor, changed, native.now); !errors.Is(err, ErrServiceAccess) || got.ID != "" || got.Key != "" {
				t.Fatal("substituted public URL publication received delivery authority", err)
			}
		})
	}
	var count int
	if err := native.d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.connector_peer_pairs WHERE publish_run_id=$1`, public.setup.PublishRunID).Scan(&count); err != nil || count != 0 {
		t.Fatal("substituted publication left a retained owner", err)
	}
}

func TestIntegrationPublicURLConnectorPairRetainsRenewalDuringRunRecovery(t *testing.T) {
	public, native, _ := publicURLConnectorPairFixture(t)
	pair := native.create(t)
	if _, err := native.d.pool.Exec(t.Context(), `UPDATE control.publish_runs SET state='starting' WHERE id=$1`, public.setup.PublishRunID); err != nil {
		t.Fatal(err)
	}
	renewal := native.request
	renewal.Action, renewal.PreviousPairID, renewal.PreviousGeneration = "renew", pair.ID, pair.DeliveryGeneration
	renewal.RequestedAt = native.now.Add(time.Second)
	native.sign(t, &renewal)
	renewed, err := native.d.RenewConnectorPeerPair(native.visitor, testVisitorIssuer, renewal, renewal.RequestedAt)
	if err != nil || renewed.ID != pair.ID || renewed.SessionKey != pair.SessionKey || renewed.DeliveryGeneration != pair.DeliveryGeneration {
		t.Fatal("publisher recovery replaced retained public URL authority", err)
	}
	fresh := native.request
	fresh.IdempotencyKey = "new-owner-during-recovery"
	native.sign(t, &fresh)
	if rejected, err := native.d.PrepareConnectorPeerPair(native.visitor, fresh, renewal.RequestedAt); !errors.Is(err, ErrServiceAccess) || rejected.ID != "" || rejected.Key != "" {
		t.Fatal("recovering public URL admitted a new connector owner", err)
	}
}

func TestIntegrationPublicURLConnectorPairRestoresOnlyCurrentOriginalNativeSource(t *testing.T) {
	for _, mutation := range []string{"parent", "device"} {
		t.Run(mutation, func(t *testing.T) {
			_, native, _ := publicURLConnectorPairFixture(t)
			pair := native.create(t)
			reauthorize := func() (VisitorSubject, ed25519.PublicKey, time.Time, error) {
				tx, err := native.d.pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, tx)
				if _, err := lockVisitorResource(t.Context(), tx, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: pair.PublicURLID}, native.now); err != nil {
					return VisitorSubject{}, nil, time.Time{}, err
				}
				saved, err := controlstatedb.New(tx).LockConnectorPeerPairForLegClaim(t.Context(), pair.ID)
				if err != nil {
					return VisitorSubject{}, nil, time.Time{}, err
				}
				return native.d.connectorPeerPairSubjectKey(t.Context(), tx, saved, native.now)
			}
			subject, key, until, err := reauthorize()
			if err != nil || subject != native.request.Subject || !bytes.Equal(key, native.key.Public().(ed25519.PublicKey)) || !until.After(native.now) {
				t.Fatal("public URL owner did not restore its original native source", err)
			}
			if mutation == "parent" {
				// another current sign-in for the same identity cannot lend its
				// deadline to this owner's revoked original session.
				newOIDCSession(t, native.d, native.now)
				_, err = native.d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET revoked_at=$2,revoked_by=identity_id
					WHERE id=(SELECT parent_control_session_id FROM control.connector_peer_pairs WHERE id=$1)`, pair.ID, native.now)
			} else {
				err = native.d.RevokeVisitorDevice(t.Context(), subject.IdentityID, subject.DeviceID, native.now)
			}
			if err != nil {
				t.Fatal(err)
			}
			subject, key, until, err = reauthorize()
			if !errors.Is(err, ErrServiceAccess) || subject.Kind != "" || len(key) != 0 || !until.IsZero() {
				t.Fatal("revoked native source retained public URL owner authority", err)
			}
		})
	}
}

func TestIntegrationPublicURLConnectorPairRechecksPublisherAfterLockWait(t *testing.T) {
	for _, mutation := range []string{"key", "grant"} {
		t.Run(mutation, func(t *testing.T) {
			public, native, publisher := publicURLConnectorPairFixture(t)
			ctx, cancel := context.WithTimeout(native.visitor, 10*time.Second)
			defer cancel()
			gate, err := native.d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockPublisherIdentity(ctx, publisher.ID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			result := make(chan error, 1)
			workers.Go(func() {
				pair, err := native.d.PrepareConnectorPeerPair(ctx, native.request, native.now)
				if pair.ID != "" || pair.Key != "" {
					result <- errors.New("changed publisher authority released a pair")
					return
				}
				result <- err
			})
			waitForPostgresBlock(t, ctx, native.d, int32(gate.Conn().PgConn().PID()), result)
			query := `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=$1`
			id, want := publisher.KeyID, ErrServiceAccess
			if mutation == "grant" {
				query, id, want = `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, publisher.GrantID, ErrPublisherIdentity
			}
			if _, err := gate.Exec(ctx, query, id, native.now); err != nil {
				t.Fatal(err)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, result); !errors.Is(err, want) {
				t.Fatal("waiting public URL owner used stale publisher authority", err)
			}
			var count int
			if err := native.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.connector_peer_pairs WHERE publish_run_id=$1`, public.setup.PublishRunID).Scan(&count); err != nil || count != 0 {
				t.Fatal("rejected waiting authority committed a pair", err)
			}
		})
	}
}
