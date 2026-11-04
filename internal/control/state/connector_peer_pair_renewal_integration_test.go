package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationConnectorPeerPairRenewalSignsSameAuthorityTransaction(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	if _, err := f.d.ConfigureService(f.visitor, pair.ServiceID, pair.Subject.IdentityID,
		ServiceMetadata{Protocol: "tcp", PublisherPool: true, TrustRevision: 1}, f.now.Add(500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := f.d.PrepareVisitorSigningKeys(f.visitor, testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}
	r := f.request
	r.Action, r.PreviousPairID, r.PreviousGeneration, r.RequestedAt = "renew", pair.ID, pair.DeliveryGeneration, f.now.Add(time.Second)
	f.sign(t, &r)
	before := connectorPairSavedAuthority(t, f.d, pair.ID)
	if denied, err := f.d.RenewConnectorPeerPair(f.visitor, "https://wrong.example.test", r, r.RequestedAt); !errors.Is(err, ErrVisitorSigningKey) || !reflect.DeepEqual(denied, ConnectorPeerPair{}) {
		t.Fatal("failed permission signing returned pair authority", err)
	}
	if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("pair renewal committed before permission signing")
	}
	// signing succeeds before the deferred constraint runs. a commit-time
	// failure must still roll back both the pair write and key retention.
	if _, err := f.d.pool.Exec(f.visitor, `CREATE FUNCTION control.reject_signed_pair_renewal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rejects pair commit' USING ERRCODE='23514'; END $$;
	    CREATE CONSTRAINT TRIGGER reject_signed_pair_renewal AFTER UPDATE ON control.connector_peer_pairs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION control.reject_signed_pair_renewal()`); err != nil {
		t.Fatal(err)
	}
	if denied, err := f.d.RenewConnectorPeerPair(f.visitor, testVisitorIssuer, r, r.RequestedAt); err == nil || !reflect.DeepEqual(denied, ConnectorPeerPair{}) {
		t.Fatal("failed commit returned signed pair authority", err)
	}
	if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("failed commit left a renewed pair without its permission result")
	}
	var beforeRetention time.Time
	if err := f.d.pool.QueryRow(f.visitor, `SELECT retain_until FROM control.visitor_token_keys WHERE retired_at IS NULL AND revoked_at IS NULL`).Scan(&beforeRetention); err != nil || beforeRetention.After(f.now) {
		t.Fatal("failed pair commit retained an unreturned permission key", err)
	}
	if _, err := f.d.pool.Exec(f.visitor, `DROP TRIGGER reject_signed_pair_renewal ON control.connector_peer_pairs; DROP FUNCTION control.reject_signed_pair_renewal()`); err != nil {
		t.Fatal(err)
	}
	renewed, err := f.d.RenewConnectorPeerPair(f.visitor, testVisitorIssuer, r, r.RequestedAt)
	if err != nil {
		t.Fatal(err)
	}
	issued := renewed.VisitorPermission
	permission := issued.Permission
	if issued.ServiceTrustRevision != renewed.Metadata.TrustRevision || issued.ServiceTrustRevision <= 1 {
		t.Fatal("renewal permission did not capture the current locked service trust revision")
	}
	if permission.Scope != (visitorscope.Scope{Kind: visitorscope.Service, ID: pair.ServiceID}) ||
		permission.Hostname != renewed.Metadata.Endpoint.Hostname || int(permission.Port) != renewed.Metadata.Endpoint.Port ||
		permission.ExpiresAt.After(renewed.ExpiresAt) || !permission.ExpiresAt.After(renewed.ObservedAt) ||
		!renewed.RunValidUntil.After(renewed.ObservedAt) || renewed.ID != pair.ID || renewed.Key != pair.Key {
		t.Fatal("renewal returned inconsistent run, pair or permission authority")
	}
	subject, err := visitortoken.ConnectorSubject(permission.Subject)
	if err != nil || subject != pair.Subject {
		t.Fatal("renewal permission changed the pinned subject", err)
	}
	keys := stateTestVisitorKeys(t, f.d, r.RequestedAt)
	visitor, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	entry := tunnelv1.ConnectorPeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorPeerVisitorStream,
		PairID: pair.ID, DeliveryID: base64.RawURLEncoding.EncodeToString(pair.DeliveryID[:]), DeliveryGeneration: pair.DeliveryGeneration,
		ServiceID: pair.ServiceID, ServiceRunID: pair.ServiceRunID, RunNumber: uint64(pair.RunNumber), Subject: subject, SourceIP: "127.0.0.1", VisitorConnectionID: visitor, MetadataRevision: uint64(renewed.Metadata.TrustRevision),
		Permission: tunnelv1.ConnectorVisitorPermission{Token: issued.Token.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(f.key.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}}
	message, err := tunnelv1.ConnectorPeerProofMessage(entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.key, message))
	expected := entry.Session()
	expected.ExpiresAt = renewed.ExpiresAt
	view := stateTestVisitorView(permission, keys, r.RequestedAt)
	view.MetadataRevision = int64(entry.MetadataRevision)
	verified, err := visitortoken.VerifyConnectorPeerSession(entry, nil, expected, view, r.RequestedAt)
	facts := verified.Facts()
	if err != nil || !verified.Valid() || facts.Scope != permission.Scope || facts.Hostname != permission.Hostname || facts.Port != permission.Port ||
		facts.VisitorPolicyRevision != permission.VisitorPolicyRevision || facts.Subject != permission.Subject || !facts.ExpiresAt.Equal(permission.ExpiresAt) {
		t.Fatal("renewal did not return the canonical signed permission", err)
	}
	var retained time.Time
	if err := f.d.pool.QueryRow(f.visitor, `SELECT retain_until FROM control.visitor_token_keys WHERE retired_at IS NULL AND revoked_at IS NULL`).Scan(&retained); err != nil || retained.Before(permission.ExpiresAt) {
		t.Fatal("renewal did not retain its verification key through permission expiry", err)
	}
}

func TestIntegrationConnectorPeerPairRenewalSigningWaitCannotRevivePair(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	if err := f.d.PrepareVisitorSigningKeys(f.visitor, testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.pool.Exec(f.visitor, `UPDATE control.connector_peer_pairs SET expires_at=$2 WHERE id=$1`, pair.ID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	r := f.request
	r.Action, r.PreviousPairID, r.PreviousGeneration, r.RequestedAt = "renew", pair.ID, pair.DeliveryGeneration, f.now.Add(time.Millisecond)
	f.sign(t, &r)
	before := connectorPairSavedAuthority(t, f.d, pair.ID)
	gate, err := f.d.pool.Begin(f.visitor)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(f.visitor, `SELECT issuer FROM control.visitor_token_issuer FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	entered := make(chan time.Time, 1)
	done, join := connectorPairWorker(t, f.visitor, func(ctx context.Context) error {
		entered <- time.Now()
		_, err := f.d.RenewConnectorPeerPair(ctx, testVisitorIssuer, r, r.RequestedAt)
		return err
	})
	defer join()
	ctx, cancel := context.WithTimeout(f.visitor, 3*time.Second)
	defer cancel()
	waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
	started := awaitIntegrationResult(t, ctx, entered)
	timer := time.NewTimer(time.Until(started.Add(time.Second + 20*time.Millisecond)))
	defer timer.Stop()
	<-timer.C
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("signing wait revived expired pair authority", err)
	}
	if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("late permission signing committed the pair renewal")
	}
	var retained time.Time
	if err := f.d.pool.QueryRow(f.visitor, `SELECT retain_until FROM control.visitor_token_keys WHERE retired_at IS NULL AND revoked_at IS NULL`).Scan(&retained); err != nil || retained.After(f.now) {
		t.Fatal("late renewal committed signing-key retention", err)
	}
}
