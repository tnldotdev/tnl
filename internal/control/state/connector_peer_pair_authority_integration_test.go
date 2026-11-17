package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectorPairCompanyFixture struct {
	database               *Database
	now                    time.Time
	connection             IdentityConnectionSecret
	parent, sibling, owner ControlSession
	request                ConnectorPeerPairRequest
	pair, personalPair     ConnectorPeerPair
	run                    ServiceRunState
	key                    ed25519.PrivateKey
	publisherGrant         string
}

func newConnectorPairCompanyFixture(t *testing.T) connectorPairCompanyFixture {
	t.Helper()
	d, now, _, leases := newConnectorPairPrerequisites(t)
	ctx := t.Context()
	owner := newOIDCSession(t, d, now)
	ownerID := owner.Identity.Identity.ID
	team, err := d.CreateTeam(ctx, authorityTeamRequest(ownerID), now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.CreateServiceAt(ctx, team.ID, ownerID, "company-pair", "company-pair", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: team.ID, ActingIdentityID: ownerID}, PublisherScope{TeamID: team.ID, Kind: "service", ServiceID: service.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "company-pair", now, ServiceRunRequest{Metadata: ServiceMetadata{Protocol: "tcp", TrustRevision: 1}})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, prepared, run, now)
	for _, slot := range run.Connections {
		lease := leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64, ActiveStreams: 0}); err != nil {
		t.Fatal(err)
	}
	identity := OIDCIdentity{Issuer: "https://company.example", Subject: "connector-pair-visitor", DisplayName: "connector pair visitor", AssertionDigest: sha256.Sum256([]byte("personal")), AssertionExpiry: now.Add(time.Hour)}
	personal, err := d.CreateOIDCControlSession(ctx, "tunnels.example.test", identity, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	person := personal.Identity.Identity.ID
	if _, err := d.CreateServiceGrant(ctx, service.ID, ownerID, "company-visitor", "identity", person, nil, now); err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(ctx, person, public, now)
	if err != nil {
		t.Fatal(err)
	}
	r := ConnectorPeerPairRequest{ServiceID: service.ID, ServiceRunID: run.RunID, RunNumber: run.RunNumber, PublisherIdentityID: publisher.ID,
		Subject: VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: person, DeviceID: device.ID}, Source: DeviceTokenSource{DeviceID: device.ID},
		IdempotencyKey: "personal-owner", Action: "create", RequestedAt: now, ExpectedRelays: testConnectorPairRelays(run, leases)}
	signConnectorPairRequest(t, &r, key)
	// save a real personal parent before enabling company policy. a later company
	// session for the same device must not replace that pair's original source.
	personalCtx := WithControlPrincipal(ctx, companyTestPrincipal(t, d, personal, now))
	personalPair, err := d.PrepareConnectorPeerPair(personalCtx, r, now)
	if err != nil {
		t.Fatal(err)
	}
	for slot := range personalPair.Relays {
		proof := testConnectorLegProof(t, personalPair, slot, now, key)
		if _, err := testClaimConnectorPeerPairLeg(t, d, ctx, personalPair.Relays[slot].RelayLease, connectorPairCompanySource, proof, now); err != nil {
			t.Fatal("personal pair could not claim before company policy", err)
		}
	}
	c := companyTestConnection(t, d, team.ID, companyTestPrincipal(t, d, owner, now), "approval", now)
	companyTestEligibility(t, d, c, person, 1, true, now)
	identity.TeamContexts = []oidc.TeamContext{{TeamID: team.ID, IdentityConnectionID: c.ID, ConnectionRevision: c.Revision, SourceID: c.SourceID, Subject: "directory/" + person, AuthenticatedAt: now.Unix()}}
	companySession := func(name string) ControlSession {
		t.Helper()
		source, err := companyBindTestIntent(t, d, identity, now)
		if err != nil {
			t.Fatal(err)
		}
		source.AssertionDigest = sha256.Sum256([]byte(name))
		session, err := d.CreateOIDCControlSession(ctx, "tunnels.example.test", source, time.Hour, 24*time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		return session
	}
	parent, sibling := companySession("parent"), companySession("sibling")
	visitor := WithControlPrincipal(ctx, companyTestPrincipal(t, d, parent, now))
	r.IdempotencyKey = "company-owner"
	signConnectorPairRequest(t, &r, key)
	if _, err := d.PrepareConnectorPeerPair(personalCtx, r, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("personal sign-in prepared a company pair", err)
	}
	pair, err := d.PrepareConnectorPeerPair(visitor, r, now)
	if err != nil {
		t.Fatal("company source could not prepare a pair", err)
	}
	if !pair.ExpiresAt.After(now) || pair.ExpiresAt.After(now.Add(5*time.Minute)) {
		t.Fatal("company pair escaped its fixed authorization lifetime")
	}
	var savedParent string
	if err := d.pool.QueryRow(ctx, `SELECT parent_control_session_id FROM control.connector_peer_pairs WHERE id=$1`, pair.ID).Scan(&savedParent); err != nil || savedParent != parent.SessionID {
		t.Fatal("pair did not save the exact authenticated parent", err)
	}
	return connectorPairCompanyFixture{database: d, now: now, connection: c, parent: parent, sibling: sibling, owner: owner,
		request: r, pair: pair, personalPair: personalPair, run: run, key: key, publisherGrant: publisher.GrantID}
}

func signConnectorPairRequest(t *testing.T, request *ConnectorPeerPairRequest, key ed25519.PrivateKey) {
	t.Helper()
	message, err := request.proof().Message()
	if err != nil {
		t.Fatal(err)
	}
	request.Signature = ed25519.Sign(key, message)
}

var connectorPairCompanySource = netip.MustParseAddr("192.0.2.10")

func (f connectorPairCompanyFixture) claim(t *testing.T, ctx context.Context, pair ConnectorPeerPair, slot int, at time.Time) (ConnectorPeerPairLegClaim, error) {
	t.Helper()
	return testClaimConnectorPeerPairLeg(t, f.database, ctx, pair.Relays[slot].RelayLease, connectorPairCompanySource, testConnectorLegProof(t, pair, slot, at, f.key), at)
}

func (f connectorPairCompanyFixture) claimBoth(t *testing.T) {
	t.Helper()
	for slot := range f.pair.Relays {
		claim, err := f.claim(t, t.Context(), f.pair, slot, f.now)
		if err != nil || claim.Key != f.pair.Key || claim.DeliveryID != f.pair.DeliveryID || claim.ExpiresAt.After(f.pair.ExpiresAt) {
			t.Fatal("company relay claim without an ambient human principal", err)
		}
	}
}

func TestIntegrationConnectorPeerPairCompanyClaims(t *testing.T) {
	f := newConnectorPairCompanyFixture(t)
	f.claimBoth(t)
	proof := testConnectorLegProof(t, f.pair, 0, f.now.Add(time.Millisecond), f.key)
	lease := f.pair.Relays[0].RelayLease
	if _, err := testClaimConnectorPeerPairLeg(t, f.database, t.Context(), lease, connectorPairCompanySource, proof, proof.RequestedAt); err != nil {
		t.Fatal("fresh company proof could not recover the same relay delivery", err)
	}
	if _, err := testClaimConnectorPeerPairLeg(t, f.database, t.Context(), lease, connectorPairCompanySource, proof, proof.RequestedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("company session restoration bypassed replay protection", err)
	}
	proof = testConnectorLegProof(t, f.pair, 0, f.now.Add(2*time.Millisecond), f.key)
	if _, err := testClaimConnectorPeerPairLeg(t, f.database, t.Context(), lease, netip.MustParseAddr("192.0.2.11"), proof, proof.RequestedAt); !errors.Is(err, ErrConnectorPeerBindingStale) {
		t.Fatal("company session restoration allowed a different observed source", err)
	}
}

func TestIntegrationConnectorPeerPairCompanyDelivery(t *testing.T) {
	f := newConnectorPairCompanyFixture(t)
	f.claimBoth(t)
	got, err := f.database.DeliverConnectorPeerPair(t.Context(), f.pair.ServiceID, f.run.RunID, f.pair.ID, f.pair.DeliveryGeneration, f.run.Token, f.now)
	if err != nil || got.Key != f.pair.Key || got.Subject != f.pair.Subject || got.DeliveryID != f.pair.DeliveryID || got.SourceIP != connectorPairCompanySource || got.ExpiresAt.After(f.pair.ExpiresAt) {
		t.Fatal("publisher could not receive company binding without a human principal", err)
	}
	report := ConnectorPeerPairPrepared{Phase: "installed", DeliveryID: got.DeliveryID, DeliveryGeneration: got.DeliveryGeneration, BindingExpiresAt: got.ExpiresAt}
	if err := f.database.ConfirmConnectorPeerPairPrepared(t.Context(), f.pair.ServiceID, f.run.RunID, f.pair.ID, f.run.Token, report, f.now); err != nil {
		t.Fatal("publisher could not report company binding installation", err)
	}
	// a current sibling sign-in cannot adopt an existing owner's request key.
	sibling := WithControlPrincipal(t.Context(), companyTestPrincipal(t, f.database, f.sibling, f.now))
	if _, err := f.database.PrepareConnectorPeerPair(sibling, f.request, f.now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("sibling session substituted the saved pair parent", err)
	}
}

func (f connectorPairCompanyFixture) foreignParentPair(t *testing.T, at time.Time) ConnectorPeerPair {
	t.Helper()
	d, ctx := f.database, t.Context()
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	if err := lockServiceAdmission(ctx, tx, f.pair.ServiceID); err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(tx)
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: f.run.RunID, ServiceID: f.pair.ServiceID})
	if err != nil {
		t.Fatal(err)
	}
	original, err := q.LockConnectorPeerPairForLegClaim(ctx, f.pair.ID)
	if err != nil {
		t.Fatal(err)
	}
	id := mustOpaqueID(t, "cpp_")
	var deliveryID [16]byte
	if _, err := rand.Read(deliveryID[:]); err != nil || deliveryID == [16]byte{} || deliveryID == f.pair.DeliveryID {
		t.Fatal("foreign-parent fixture did not select an independent delivery identifier", err)
	}
	// preserve actual key material, but authenticate each ciphertext with the new
	// pair's own context. copying ciphertext would fail before testing authority.
	reseal := func(scope func(string) string, keyID string, ciphertext, digest []byte) []byte {
		t.Helper()
		secret, _, err := d.storageKey.Open(keyID, scope(original.ID), ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(secret)
		hash := sha256.Sum256(secret)
		if len(secret) != 32 || !bytes.Equal(hash[:], digest) {
			t.Fatal("foreign-parent fixture lost its actual key material")
		}
		sealed, err := d.storageKey.Seal(scope(id), secret)
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}
	keyCiphertext := reseal(connectorPeerPairKeyContext, original.StorageKeyID, original.KeyCiphertext, original.KeyDigest)
	sessionCiphertext := reseal(connectorPeerSessionKeyContext, original.SessionKeyStorageKeyID.String, original.SessionKeyCiphertext, original.SessionKeyDigest)
	request := f.request
	request.IdempotencyKey = id
	message, err := request.proof().Message()
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256(message)
	// insert the foreign parent from the beginning; never update an immutable
	// owner or disable its trigger to manufacture the runtime authority contrast.
	row, err := q.InsertConnectorPeerPair(ctx, controlstatedb.InsertConnectorPeerPairParams{
		ID: id, ServiceID: original.ServiceID, ServiceRunID: original.ServiceRunID, RunNumber: original.RunNumber,
		PublisherIdentityID: original.PublisherIdentityID, SubjectKind: original.SubjectKind, SubjectID: original.SubjectID,
		ParentControlSessionID: text(f.owner.SessionID), OwnerKey: id, IdempotencyKey: id, OwnerPublicKey: original.OwnerPublicKey,
		RequestDigest: requestDigest[:], KeyDigest: original.KeyDigest, KeyCiphertext: keyCiphertext,
		DeliveryID: deliveryID[:], StorageKeyID: d.storageKey.CurrentID(), Slots: original.Slots,
		Now: original.CreatedAt, RequestAt: original.LastRequestAt, ExpiresAt: original.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	row, err = q.InitializeConnectorPeerSession(ctx, controlstatedb.InitializeConnectorPeerSessionParams{
		ID: id, Ciphertext: sessionCiphertext, Digest: original.SessionKeyDigest,
		StorageKeyID: text(d.storageKey.CurrentID()), TrustRevision: original.TrustRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := original
	expected.ID, expected.ParentControlSessionID = id, text(f.owner.SessionID)
	expected.OwnerKey, expected.IdempotencyKey, expected.RequestDigest = id, id, requestDigest[:]
	expected.KeyCiphertext, expected.SessionKeyCiphertext, expected.DeliveryID = keyCiphertext, sessionCiphertext, deliveryID[:]
	expected.StorageKeyID, expected.SessionKeyStorageKeyID = d.storageKey.CurrentID(), text(d.storageKey.CurrentID())
	expected.DeliveryGeneration, expected.HighWaterGeneration = row.DeliveryGeneration, row.DeliveryGeneration
	if row.DeliveryGeneration <= original.DeliveryGeneration || !reflect.DeepEqual(row, expected) {
		t.Fatal("foreign-parent insertion changed unrelated owner, binding, or deadline facts")
	}
	claims, err := q.ReadConnectorPeerBindingClaims(ctx, controlstatedb.ReadConnectorPeerBindingClaimsParams{PairID: original.ID, DeliveryGeneration: original.DeliveryGeneration})
	if err != nil || len(claims) != 2 {
		t.Fatal("foreign-parent fixture did not retain both current leg claims", err)
	}
	for _, claim := range claims {
		source, err := d.openConnectorSource(ctx, q, original.ServiceID, claim)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := d.storageKey.Seal(connectorSourceContext(id, row.DeliveryGeneration, claim.ConnectionSlot), source.AsSlice())
		if err != nil {
			t.Fatal(err)
		}
		_, err = q.SaveConnectorPeerPairLegClaim(ctx, controlstatedb.SaveConnectorPeerPairLegClaimParams{
			PairID: id, ConnectionSlot: claim.ConnectionSlot, RequestedAt: claim.RequestedAt, CheckedAt: claim.CheckedAt, ConfirmedUntil: claim.ConfirmedUntil,
			NonceDigest: claim.NonceDigest, SourceDigest: claim.SourceDigest, SourceCiphertext: sealed, SourceStorageKeyID: d.storageKey.CurrentID(),
			RelayID: claim.RelayID, RelayRunID: claim.RelayRunID, RelayLeaseRevision: claim.RelayLeaseRevision, DeliveryGeneration: row.DeliveryGeneration,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if key, err := d.connectorPeerSecret(row.StorageKeyID, connectorPeerPairKeyContext(id), row.KeyCiphertext, row.KeyDigest); err != nil || key != f.pair.Key {
		t.Fatal("foreign-parent fixture has invalid pair ciphertext", err)
	}
	if key, err := d.connectorPeerSessionKey(row); err != nil || key != f.pair.SessionKey {
		t.Fatal("foreign-parent fixture has invalid session ciphertext", err)
	}
	parent, err := q.GetVisitorParentSession(ctx, f.owner.SessionID)
	if err != nil || parent.IdentityID == f.pair.Subject.IdentityID || parent.RevokedAt.Valid ||
		!parent.AccessExpiresAt.Time.After(at) || !parent.RefreshExpiresAt.Time.After(at) {
		t.Fatal("foreign-parent fixture did not isolate a live different identity", err)
	}
	var deviceIdentity string
	if err := tx.QueryRow(ctx, `SELECT identity_id FROM control.visitor_devices WHERE id=$1 AND revoked_at IS NULL`, row.SubjectID).Scan(&deviceIdentity); err != nil ||
		row.SubjectKind != tunnelv1.VisitorHumanDevice || deviceIdentity != f.pair.Subject.IdentityID || !bytes.Equal(row.OwnerPublicKey, f.key.Public().(ed25519.PublicKey)) {
		t.Fatal("foreign-parent fixture lost its actual enrolled subject or key", err)
	}
	// change only a row copy for this read-only contrast. a current full binding
	// proves that no run, grant, key, slot, claim, or expiry prerequisite masks the
	// persisted foreign parent's identity mismatch.
	matched := row
	matched.ParentControlSessionID = original.ParentControlSessionID
	binding, err := d.connectorPeerPairBinding(ctx, tx, run, matched, at)
	if err != nil || !binding.claimsCurrent || binding.subject != f.pair.Subject || binding.relays != f.pair.Relays ||
		!bytes.Equal(binding.publicKey, row.OwnerPublicKey) || binding.source != connectorPairCompanySource ||
		!binding.expiresAt.After(at) || binding.expiresAt.After(f.pair.ExpiresAt) {
		t.Fatal("matching-parent contrast lacks an otherwise current binding", err)
	}
	if _, key, _, err := connectorPeerPairSubjectKey(ctx, tx, row, at); err != ErrServiceAccess || len(key) != 0 {
		t.Fatal("foreign parent did not hit the saved-parent identity fence", err)
	}
	if _, err := d.connectorPeerPairBinding(ctx, tx, run, row, at); err != ErrServiceAccess {
		t.Fatal("foreign parent retained a current binding", err)
	}
	if _, err := tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	pair := f.pair
	pair.ID, pair.DeliveryID, pair.DeliveryGeneration = id, deliveryID, row.DeliveryGeneration
	return pair
}

func TestIntegrationConnectorPeerPairSavedParentFences(t *testing.T) {
	for _, name := range []string{"revoked", "access expired", "refresh expired", "company proof expired", "eligibility revoked", "eligibility expired", "another identity parent", "personal sibling parent"} {
		t.Run(name, func(t *testing.T) {
			f := newConnectorPairCompanyFixture(t)
			f.claimBoth(t)
			d, ctx, at := f.database, t.Context(), f.now.Add(time.Second)
			sibling := WithControlPrincipal(ctx, companyTestPrincipal(t, d, f.sibling, f.now))
			originalID := f.pair.ID
			var originalBefore []byte
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := d.pool.Exec(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "revoked":
				if err := d.RevokeControlSession(ctx, companyTestPrincipal(t, d, f.parent, f.now), at); err != nil {
					t.Fatal(err)
				}
			case "access expired":
				exec(`UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, f.parent.SessionID, at)
			case "refresh expired":
				exec(`UPDATE control.control_sessions SET access_expires_at=$2,refresh_expires_at=$2 WHERE id=$1`, f.parent.SessionID, at)
			case "company proof expired":
				exec(`UPDATE control.company_session_contexts SET expires_at=$2 WHERE session_id=$1`, f.parent.SessionID, at)
			case "eligibility revoked", "eligibility expired":
				r := ProvisionCompanyEligibilityRequest{TeamID: f.connection.TeamID, IdentityConnectionID: f.connection.ID, ConnectionRevision: f.connection.Revision,
					IdentityID: f.pair.Subject.IdentityID, Subject: "directory/" + f.pair.Subject.IdentityID, Revision: 2, Eligible: name != "eligibility revoked", ValidUntil: at, MemberSlug: "managed-member"}
				if err := d.ProvisionCompanyEligibility(ctx, f.connection.ProvisioningToken, r, f.now); err != nil {
					t.Fatal(err)
				}
			case "another identity parent":
				originalBefore = connectorPairSavedAuthority(t, d, originalID)
				_, err := d.pool.Exec(ctx, `UPDATE control.connector_peer_pairs SET parent_control_session_id=$2 WHERE id=$1`, originalID, f.owner.SessionID)
				var constraint *pgconn.PgError
				if !errors.As(err, &constraint) || constraint.Code != "23514" || constraint.Message != "connector pair owner scope is immutable" {
					t.Fatal("saved parent update did not hit the immutable owner fence", err)
				}
				if !bytes.Equal(originalBefore, connectorPairSavedAuthority(t, d, originalID)) {
					t.Fatal("rejected parent update changed saved authority")
				}
				f.pair = f.foreignParentPair(t, at)
				if !bytes.Equal(originalBefore, connectorPairSavedAuthority(t, d, originalID)) {
					t.Fatal("foreign-parent insertion changed the original owner")
				}
			case "personal sibling parent":
				// this pair really was created under personal sign-in, before the
				// company policy was enabled. a fresh sibling cannot lend its proof.
				f.pair = f.personalPair
			}
			before := connectorPairSavedAuthority(t, d, f.pair.ID)
			for _, callCtx := range []context.Context{ctx, sibling} {
				// the signed request was fresh before authority changed, but arrives
				// afterward. current state, not its signing time, governs delivery.
				proof := testConnectorLegProof(t, f.pair, 0, f.now.Add(time.Millisecond), f.key)
				claim, err := testClaimConnectorPeerPairLeg(t, d, callCtx, f.pair.Relays[0].RelayLease, connectorPairCompanySource, proof, at)
				if !errors.Is(err, ErrServiceAccess) || claim.Key != "" {
					t.Fatal("invalid saved parent borrowed caller authority for a relay claim", err)
				}
				got, err := d.DeliverConnectorPeerPair(callCtx, f.pair.ServiceID, f.run.RunID, f.pair.ID, f.pair.DeliveryGeneration, f.run.Token, at)
				if !errors.Is(err, ErrServiceAccess) || got.Key != "" {
					t.Fatal("invalid saved parent borrowed caller authority for delivery", err)
				}
				report := ConnectorPeerPairPrepared{Phase: "installed", DeliveryID: f.pair.DeliveryID, DeliveryGeneration: f.pair.DeliveryGeneration, BindingExpiresAt: f.pair.ExpiresAt}
				if err := d.ConfirmConnectorPeerPairPrepared(callCtx, f.pair.ServiceID, f.run.RunID, f.pair.ID, f.run.Token, report, at); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("invalid saved parent authorized a publisher report", err)
				}
				if !bytes.Equal(before, connectorPairSavedAuthority(t, d, f.pair.ID)) {
					t.Fatal("rejected saved-parent operations changed durable authority")
				}
				if originalBefore != nil && !bytes.Equal(originalBefore, connectorPairSavedAuthority(t, d, originalID)) {
					t.Fatal("rejected foreign-parent operations changed the original owner")
				}
			}
			var claims int
			var prepared bool
			if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.connector_peer_pair_leg_claims WHERE pair_id=$1 AND requested_at>$2`, f.pair.ID, f.now).Scan(&claims); err != nil || claims != 0 {
				t.Fatal("rejected authority advanced a relay claim", err)
			}
			if err := d.pool.QueryRow(ctx, `SELECT publisher_prepared_until IS NOT NULL FROM control.connector_peer_pairs WHERE id=$1`, f.pair.ID).Scan(&prepared); err != nil || prepared {
				t.Fatal("rejected authority advanced publisher readiness", err)
			}
		})
	}
}

func TestIntegrationConnectorPeerPairSavedParentDeadlines(t *testing.T) {
	for _, name := range []string{"access", "refresh", "company proof", "eligibility", "run", "publisher grant", "certificate", "pair"} {
		t.Run(name, func(t *testing.T) {
			f := newConnectorPairCompanyFixture(t)
			d, ctx := f.database, t.Context()
			// state operations include their elapsed work in checked_at. advance
			// this synthetic clock between calls instead of making delivery appear
			// to precede the claims it just saved. the three-second bound is fixed.
			started := time.Now()
			checkedNow := func() time.Time { return f.now.Add(time.Since(started)) }
			deadline := f.now.Add(3 * time.Second)
			queries := map[string]struct {
				query, id string
			}{
				"access":          {`UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, f.parent.SessionID},
				"refresh":         {`UPDATE control.control_sessions SET access_expires_at=$2,refresh_expires_at=$2 WHERE id=$1`, f.parent.SessionID},
				"company proof":   {`UPDATE control.company_session_contexts SET expires_at=$2 WHERE session_id=$1`, f.parent.SessionID},
				"eligibility":     {`UPDATE control.company_eligibility SET valid_until=$2 WHERE identity_id=$1`, f.pair.Subject.IdentityID},
				"run":             {`UPDATE control.service_runs SET serving_until=$2 WHERE id=$1`, f.run.RunID},
				"publisher grant": {`UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, f.publisherGrant},
				"certificate":     {`UPDATE control.service_runs SET certificate_expires_at=$2 WHERE id=$1`, f.run.RunID},
				"pair":            {`UPDATE control.connector_peer_pairs SET expires_at=$2 WHERE id=$1`, f.pair.ID},
			}
			q := queries[name]
			if _, err := d.pool.Exec(ctx, q.query, q.id, deadline); err != nil {
				t.Fatal(err)
			}
			for slot := range f.pair.Relays {
				claim, err := f.claim(t, ctx, f.pair, slot, checkedNow())
				if err != nil || !claim.ExpiresAt.Equal(deadline) {
					t.Fatal("relay claim outlived current saved authority", err)
				}
			}
			got, err := d.DeliverConnectorPeerPair(ctx, f.pair.ServiceID, f.run.RunID, f.pair.ID, f.pair.DeliveryGeneration, f.run.Token, checkedNow())
			if err != nil || !got.ExpiresAt.Equal(deadline) {
				t.Fatal("publisher delivery outlived current saved authority", err)
			}
			report := ConnectorPeerPairPrepared{Phase: "installed", DeliveryID: f.pair.DeliveryID, DeliveryGeneration: f.pair.DeliveryGeneration, BindingExpiresAt: deadline.Add(time.Microsecond)}
			if err := d.ConfirmConnectorPeerPairPrepared(ctx, f.pair.ServiceID, f.run.RunID, f.pair.ID, f.run.Token, report, checkedNow()); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("publisher report widened the checked binding deadline", err)
			}
			report.BindingExpiresAt = deadline
			if err := d.ConfirmConnectorPeerPairPrepared(ctx, f.pair.ServiceID, f.run.RunID, f.pair.ID, f.run.Token, report, checkedNow()); err != nil {
				t.Fatal(err)
			}
			var authorized, saved time.Time
			wantSaved := f.pair.ExpiresAt
			if name == "pair" {
				wantSaved = deadline
			}
			if err := d.pool.QueryRow(ctx, `SELECT last_authorized_at,expires_at FROM control.connector_peer_pairs WHERE id=$1`, f.pair.ID).Scan(&authorized, &saved); err != nil || !authorized.Equal(f.now) || !saved.Equal(wantSaved) {
				t.Fatal("claim, delivery, or installation report renewed the pair", err)
			}
			// only a new authenticated pair authorization may extend the pair;
			// lengthening this exact parent's session cannot do so by itself.
			if _, err := d.pool.Exec(ctx, `UPDATE control.control_sessions SET access_expires_at=$2,refresh_expires_at=$3 WHERE id=$1`, f.parent.SessionID, f.now.Add(time.Hour), f.now.Add(24*time.Hour)); err != nil {
				t.Fatal(err)
			}
			got, err = d.DeliverConnectorPeerPair(ctx, f.pair.ServiceID, f.run.RunID, f.pair.ID, f.pair.DeliveryGeneration, f.run.Token, checkedNow())
			if err != nil || got.ExpiresAt.After(saved) {
				t.Fatal("later parent lifetime extended a fixed pair", err)
			}
		})
	}
}
