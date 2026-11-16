package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func connectorRetireRequest(t *testing.T, f connectorPairFixture, pair ConnectorPeerPair, at time.Time) ConnectorPeerPairRetireRequest {
	t.Helper()
	p := tunnelv1.ConnectorPeerPairRetireProof{ServiceID: pair.ServiceID, ServiceRunID: pair.ServiceRunID, RunNumber: pair.RunNumber,
		PublisherIdentityID: pair.PublisherIdentityID, PairID: pair.ID, DeliveryID: base64.RawURLEncoding.EncodeToString(pair.DeliveryID[:]),
		IdempotencyKey: f.request.IdempotencyKey, RequestedAt: at}
	return signConnectorRetirement(t, f.key, pair.SessionKey, p)
}

func signConnectorRetirement(t *testing.T, key ed25519.PrivateKey, encodedSession string, p tunnelv1.ConnectorPeerPairRetireProof) ConnectorPeerPairRetireRequest {
	t.Helper()
	session, err := base64.RawURLEncoding.Strict().DecodeString(encodedSession)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(session)
	mac, err := p.SessionProof(session)
	if err != nil {
		t.Fatal(err)
	}
	message, err := p.Message(mac)
	if err != nil {
		t.Fatal(err)
	}
	return ConnectorPeerPairRetireRequest{Proof: p, SessionProof: mac, Signature: ed25519.Sign(key, message)}
}

func TestIntegrationConnectorPeerPairRetirementExactReplayAndFences(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	siblingRequest := f.request
	siblingRequest.IdempotencyKey = "retirement-sibling"
	f.sign(t, &siblingRequest)
	sibling, err := f.d.PrepareConnectorPeerPair(f.visitor, siblingRequest, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for slot := range 2 {
		f.claim(t, pair, slot, f.now.Add(time.Second))
	}
	f.report(t, pair, pair.ExpiresAt, f.now.Add(2*time.Second))
	retire := connectorRetireRequest(t, f, pair, f.now.Add(4*time.Second))
	prepare := connectorRebindRequest(t, f, pair, "prepare", f.now.Add(3*time.Second))
	rebound, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, prepare, prepare.Proof.RequestedAt)
	if err != nil || rebound.Pending == nil {
		t.Fatal("valid rebind setup", err)
	}
	siblingBefore := connectorPairSavedAuthority(t, f.d, sibling.ID)
	var expires, replay time.Time
	var snapshot []byte
	if err := f.d.pool.QueryRow(t.Context(), `SELECT expires_at,replay_fence_until,owner_public_key FROM control.connector_peer_pairs WHERE id=$1`, pair.ID).Scan(&expires, &replay, &snapshot); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot, f.key.Public().(ed25519.PublicKey)) {
		t.Fatal("pair did not capture the actual verified enrolled key")
	}
	result, err := f.d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, pair.ID, retire, retire.Proof.RequestedAt)
	if err != nil || result.OwnerRevision != 2 || result.PairID != pair.ID || result.Retirement.RetiredAt.IsZero() {
		t.Fatal("exact retirement did not commit", err)
	}
	for _, at := range []time.Time{f.now.Add(5 * time.Second), f.now.Add(6 * time.Second)} {
		retry, err := f.d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, pair.ID, retire, at)
		if err != nil || !retry.Retirement.RetiredAt.Equal(result.Retirement.RetiredAt) ||
			!retry.Retirement.RetainedUntil.Equal(result.Retirement.RetainedUntil) {
			t.Fatal("identical lost-reply retry changed the retirement or window", err)
		}
	}
	var claims, pending, audits int
	var afterExpires, afterReplay time.Time
	if err := f.d.pool.QueryRow(t.Context(), `SELECT expires_at,replay_fence_until,
		(SELECT count(*) FROM control.connector_peer_pair_leg_claims WHERE pair_id=$1),
		(SELECT count(*) FROM control.connector_peer_pending_bindings WHERE pair_id=$1),
		(SELECT count(*) FROM control.connector_peer_audit_bindings WHERE pair_id=$1 AND retired_at IS NOT NULL)
		FROM control.connector_peer_pairs WHERE id=$1`, pair.ID).Scan(&afterExpires, &afterReplay, &claims, &pending, &audits); err != nil {
		t.Fatal(err)
	}
	if !afterExpires.Equal(expires) || !afterReplay.Equal(replay) || claims != 0 || pending != 0 || audits != 1 ||
		!bytes.Equal(siblingBefore, connectorPairSavedAuthority(t, f.d, sibling.ID)) {
		t.Fatal("retirement changed a deadline, sibling, parent, or failed to retire exact children")
	}
	before := connectorPairSavedAuthority(t, f.d, pair.ID)
	changed := retire.Proof
	changed.RequestedAt = changed.RequestedAt.Add(time.Microsecond)
	if _, err := f.d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, pair.ID,
		signConnectorRetirement(t, f.key, pair.SessionKey, changed), f.now.Add(7*time.Second)); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("changed reply-loss request did not conflict", err)
	}
	crossed := retire.Proof
	crossed.PairID, crossed.DeliveryID, crossed.IdempotencyKey = sibling.ID, base64.RawURLEncoding.EncodeToString(sibling.DeliveryID[:]), siblingRequest.IdempotencyKey
	if _, err := f.d.RetireConnectorPeerPair(t.Context(), sibling.ServiceID, sibling.ID,
		signConnectorRetirement(t, f.key, pair.SessionKey, crossed), f.now.Add(7*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("shared enrolled signer plus another pair key retired a sibling", err)
	}
	missing := retire.Proof
	missing.PairID = "cpp_1234567890123456789012"
	if missing.PairID == pair.ID || missing.PairID == sibling.ID {
		t.Fatal("missing-pair fixture collided with an actual pair")
	}
	if _, err := f.d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, missing.PairID,
		signConnectorRetirement(t, f.key, pair.SessionKey, missing), f.now.Add(7*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("missing pair became confirmed retirement", err)
	}
	renew := f.request
	renew.Action, renew.PreviousPairID, renew.PreviousGeneration, renew.RequestedAt = "renew", pair.ID, pair.DeliveryGeneration, f.now.Add(7*time.Second)
	f.sign(t, &renew)
	if _, err := f.d.RenewConnectorPeerPair(f.visitor, testVisitorIssuer, renew, renew.RequestedAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("terminal pair renewed", err)
	}
	for _, action := range []string{"create", "replace"} {
		request := f.request
		if action == "replace" {
			request.Action, request.PreviousPairID, request.PreviousGeneration = action, pair.ID, pair.DeliveryGeneration
			request.RequestedAt = f.now.Add(7 * time.Second)
			f.sign(t, &request)
		}
		if _, err := f.d.PrepareConnectorPeerPair(f.visitor, request, f.now.Add(7*time.Second)); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("positive idempotent action bypassed retirement", action, err)
		}
	}
	for _, phase := range []string{"inspect", "prepare", "activate", "abort"} {
		initialPhase := phase
		if phase == "activate" {
			initialPhase = "inspect"
		}
		request := connectorRebindRequest(t, f, pair, initialPhase, f.now.Add(7*time.Second))
		if phase == "activate" || phase == "abort" {
			request.Proof.Phase = phase
			request.Proof.OperationID = rebound.OperationID
			request.Proof.ExpectedGeneration = rebound.Pending.DeliveryGeneration
			if phase == "activate" {
				request.Proof.BindingChallenge = rebound.Pending.BindingChallenge
				request.Proof.PathProofs = connectorRebindProofs(t, *rebound.Pending, 0)
			}
			request = signConnectorRebind(t, f, request.Proof)
		}
		if _, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, request, f.now.Add(7*time.Second)); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("network phase bypassed retirement", phase, err)
		}
	}
	if _, err := f.d.DeliverConnectorPeerPair(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, pair.DeliveryGeneration, f.run.Token, f.now.Add(7*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("retired pair disclosed keys", err)
	}
	if err := f.d.ConfirmConnectorPeerPairPrepared(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, f.run.Token,
		ConnectorPeerPairPrepared{Phase: "installed", DeliveryID: pair.DeliveryID, DeliveryGeneration: pair.DeliveryGeneration, BindingExpiresAt: pair.ExpiresAt},
		f.now.Add(7*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("retired installation revived authority", err)
	}
	proof := testConnectorLegProof(t, pair, 0, f.now.Add(7*time.Second), f.key)
	if _, err := testClaimConnectorPeerPairLeg(t, f.d, t.Context(), pair.Relays[0].RelayLease,
		netip.MustParseAddr("192.0.2.10"), proof, f.now.Add(7*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("retired pair acquired a new relay claim", err)
	}
	if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("denied positive actions or changed retries modified terminal state")
	}
	if _, err := f.d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, pair.ID, retire, result.Retirement.RetainedUntil); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("retry restarted a spent retention window", err)
	}
}

func TestIntegrationConnectorPeerPairRetirementAfterAuthorityEnds(t *testing.T) {
	for _, change := range []string{"session expiry", "session revocation", "device revocation", "pair expiry", "closed run",
		"publisher grant revocation", "disabled service", "deleted service", "deleted team"} {
		t.Run(change, func(t *testing.T) {
			f := newConnectorPairFixture(t)
			pair := f.create(t)
			r := f.request
			r.IdempotencyKey = "still-separate"
			f.sign(t, &r)
			sibling, err := f.d.PrepareConnectorPeerPair(f.visitor, r, f.now)
			if err != nil {
				t.Fatal(err)
			}
			at := f.now.Add(2 * time.Second)
			retire := connectorRetireRequest(t, f, pair, at)
			parent := f.visitor.Value(controlPrincipalKey{}).(ControlPrincipal)
			switch change {
			case "session expiry":
				_, err = f.d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, parent.SessionID, f.now.Add(time.Second))
			case "session revocation":
				err = f.d.RevokeControlSession(t.Context(), parent, at)
			case "device revocation":
				err = f.d.RevokeVisitorDevice(f.visitor, pair.Subject.IdentityID, pair.Subject.DeviceID, at)
			case "pair expiry":
				_, err = f.d.pool.Exec(t.Context(), `UPDATE control.connector_peer_pairs SET expires_at=created_at+interval '1 microsecond' WHERE id=$1`, pair.ID)
			case "closed run":
				err = f.d.CloseServiceRun(t.Context(), pair.ServiceID, pair.ServiceRunID, f.run.Token, at)
			case "publisher grant revocation":
				_, err = f.d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=(SELECT publisher_grant_id FROM control.service_runs WHERE id=$1)`, pair.ServiceRunID, at)
			case "disabled service":
				_, err = f.d.pool.Exec(t.Context(), `UPDATE control.services SET enabled=false WHERE id=$1`, pair.ServiceID)
			case "deleted service":
				_, err = f.d.pool.Exec(t.Context(), `UPDATE control.services SET enabled=false,deleted_at=$2 WHERE id=$1`, pair.ServiceID, at)
			case "deleted team":
				_, err = f.d.pool.Exec(t.Context(), `UPDATE control.teams SET deleted_at=$2 WHERE id=(SELECT team_id FROM control.services WHERE id=$1)`, pair.ServiceID, at)
			}
			if err != nil {
				t.Fatal("authority-ending fixture", err)
			}
			if _, err := f.d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, pair.ID, retire, at); err != nil {
				t.Fatal("negative-only retirement required renewed serving authority", err)
			}
			page, err := f.d.ListConnectorPeerPairs(t.Context(), pair.ServiceID, pair.ServiceRunID, "", f.run.Token, at.Add(time.Second))
			if err != nil {
				t.Fatal("exact stored token could not observe retirement", err)
			}
			negativeOnly := change == "closed run" || change == "publisher grant revocation" || change == "disabled service" || change == "deleted service" || change == "deleted team"
			found := false
			for _, item := range page.Items {
				if item.PairID == pair.ID {
					found = item.Retired && item.OwnerRevision == 2 && item.Retirement != nil && item.OwnerAuthority == nil
				}
				if negativeOnly && (item.PairID == sibling.ID || !item.Retired || item.OwnerAuthority != nil) {
					t.Fatal("negative-only token read returned a positive preparation or permission")
				}
			}
			if !found {
				t.Fatal("retirement became omission instead of an explicit terminal fact")
			}
			if _, err := f.d.ListConnectorPeerPairs(t.Context(), pair.ServiceID, pair.ServiceRunID, "", "wrong-run-token", at); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("wrong token read retirement", err)
			}
			before := connectorPairSavedAuthority(t, f.d, pair.ID)
			if _, err := f.d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, pair.ID, retire, at.Add(time.Second)); err != nil ||
				!bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
				t.Fatal("post-revocation identical retry mutated state", err)
			}
		})
	}
}

func TestIntegrationConnectorPeerPairRetirementReplacementAndAtomicRollback(t *testing.T) {
	t.Run("replacement wins", func(t *testing.T) {
		f := newConnectorPairFixture(t)
		pair := f.create(t)
		retire := connectorRetireRequest(t, f, pair, f.now.Add(time.Second))
		replace := f.request
		replace.Action, replace.PreviousPairID, replace.PreviousGeneration, replace.RequestedAt = "replace", pair.ID, pair.DeliveryGeneration, f.now.Add(time.Second)
		f.sign(t, &replace)
		successor, err := f.d.PrepareConnectorPeerPair(f.visitor, replace, replace.RequestedAt)
		if err != nil {
			t.Fatal(err)
		}
		before := connectorPairSavedAuthority(t, f.d, successor.ID)
		if _, err := f.d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, pair.ID, retire, f.now.Add(2*time.Second)); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("absent predecessor became confirmed retirement", err)
		}
		crossed := retire.Proof
		crossed.PairID, crossed.DeliveryID = successor.ID, base64.RawURLEncoding.EncodeToString(successor.DeliveryID[:])
		if _, err := f.d.RetireConnectorPeerPair(t.Context(), successor.ServiceID, successor.ID,
			signConnectorRetirement(t, f.key, pair.SessionKey, crossed), f.now.Add(2*time.Second)); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("predecessor key retired its replacement", err)
		}
		if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, successor.ID)) {
			t.Fatal("old retirement followed the stable owner key to a replacement")
		}
	})
	t.Run("deferred rollback", func(t *testing.T) {
		f := newConnectorPairFixture(t)
		pair := f.create(t)
		f.claim(t, pair, 0, f.now.Add(time.Second))
		rebind := connectorRebindRequest(t, f, pair, "prepare", f.now.Add(2*time.Second))
		if _, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, rebind, rebind.Proof.RequestedAt); err != nil {
			t.Fatal(err)
		}
		before := connectorPairSavedAuthority(t, f.d, pair.ID)
		if _, err := f.d.pool.Exec(t.Context(), `CREATE FUNCTION control.reject_pair_retirement() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN IF NEW.owner_revision=2 THEN RAISE EXCEPTION 'retirement rollback fixture' USING ERRCODE='23514'; END IF; RETURN NEW; END $$;
			CREATE CONSTRAINT TRIGGER reject_pair_retirement AFTER UPDATE ON control.connector_peer_pairs
			DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION control.reject_pair_retirement()`); err != nil {
			t.Fatal(err)
		}
		retire := connectorRetireRequest(t, f, pair, f.now.Add(3*time.Second))
		_, err := f.d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, pair.ID, retire, retire.Proof.RequestedAt)
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23514" || !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
			t.Fatal("failed terminal transaction left partial retirement or child deletion", err)
		}
	})
}

func TestIntegrationConnectorPeerPairRetirementStorageAndOneWindow(t *testing.T) {
	t.Run("immutable terminal state", func(t *testing.T) {
		f := newConnectorPairFixture(t)
		pair := f.create(t)
		for _, query := range []string{
			`UPDATE control.connector_peer_pairs SET owner_public_key=decode(repeat('01',32),'hex') WHERE id=$1`,
			`UPDATE control.connector_peer_pairs SET owner_public_key=NULL WHERE id=$1`,
			`UPDATE control.connector_peer_pairs SET owner_revision=2 WHERE id=$1`,
			`UPDATE control.connector_peer_pairs SET retired_at=last_authorized_at WHERE id=$1`,
		} {
			if _, err := f.d.pool.Exec(t.Context(), query, pair.ID); err == nil {
				t.Fatal("storage accepted a changed snapshot or incomplete terminal transition")
			}
		}
		retire := connectorRetireRequest(t, f, pair, f.now.Add(time.Second))
		if _, err := f.d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, pair.ID, retire, retire.Proof.RequestedAt); err != nil {
			t.Fatal(err)
		}
		for _, change := range []string{
			`owner_revision=1,retired_at=NULL,retire_request_digest=NULL`,
			`replay_fence_until=replay_fence_until+interval '1 second',last_request_at=last_request_at+interval '1 second'`,
			`expires_at=expires_at-interval '1 microsecond'`,
			`high_water_generation=high_water_generation+1`,
			`publisher_prepared_until=expires_at`,
		} {
			if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.connector_peer_pairs SET `+change+` WHERE id=$1`, pair.ID); err == nil {
				t.Fatal("terminal state or retention changed")
			}
		}
	})
	t.Run("lock wait spends original retention", func(t *testing.T) {
		f := newConnectorPairFixture(t)
		pair := f.create(t)
		until := f.now.Add(time.Second)
		if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.connector_peer_pairs
			SET expires_at=$2,last_request_at=$2::timestamptz-interval '5 minutes',replay_fence_until=$2 WHERE id=$1`, pair.ID, until); err != nil {
			t.Fatal(err)
		}
		before := connectorPairSavedAuthority(t, f.d, pair.ID)
		retire := connectorRetireRequest(t, f, pair, f.now)
		gate, err := f.d.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackTestTransaction(t, gate)
		if _, err := gate.Exec(t.Context(), `SELECT id FROM control.service_runs WHERE id=$1 FOR UPDATE`, pair.ServiceRunID); err != nil {
			t.Fatal(err)
		}
		entered := make(chan time.Time, 1)
		done, join := connectorPairWorker(t, t.Context(), func(ctx context.Context) error {
			entered <- time.Now()
			_, err := f.d.RetireConnectorPeerPair(ctx, pair.ServiceID, pair.ID, retire, f.now)
			return err
		})
		defer join()
		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		defer cancel()
		waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
		started := awaitIntegrationResult(t, ctx, entered)
		timer := time.NewTimer(time.Until(started.Add(time.Second + 10*time.Millisecond)))
		defer timer.Stop()
		<-timer.C
		if err := gate.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceAccess) || !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
			t.Fatal("lock wait minted another cleanup or retention window", err)
		}
	})
}

func TestIntegrationConnectorPeerPairRetirementSignaturePrecedesSecretAndDatabaseFailure(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	retire := connectorRetireRequest(t, f, pair, f.now.Add(time.Second))
	// corruption is not a new key or permission. a bad original signature must
	// fail before opening even this deliberately unusable stored ciphertext.
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.connector_peer_pairs SET session_key_ciphertext=decode('00','hex') WHERE id=$1`, pair.ID); err != nil {
		t.Fatal(err)
	}
	invalid := retire
	invalid.Signature = bytes.Clone(retire.Signature)
	invalid.Signature[0] ^= 1
	if _, err := f.d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, pair.ID, invalid, retire.Proof.RequestedAt); err != ErrServiceAccess {
		t.Fatal("invalid signature reached stored-secret decryption", err)
	}
	if _, err := f.d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, pair.ID, retire, retire.Proof.RequestedAt); err == nil || connectorPeerAuthorityDenied(err) {
		t.Fatal("stored-secret failure became negative retirement evidence", err)
	}
	f.d.pool.Close()
	if page, err := f.d.ListConnectorPeerPairs(t.Context(), pair.ServiceID, pair.ServiceRunID, "", f.run.Token, f.now.Add(2*time.Second)); err == nil || connectorPeerAuthorityDenied(err) || len(page.Items) != 0 {
		t.Fatal("database outage became a retired disposition", err)
	}
}

func TestIntegrationConnectorPeerPairRetirementConcurrentWorkloadRevocation(t *testing.T) {
	for _, order := range []string{"revoke first", "retire first", "concurrent"} {
		t.Run(order, func(t *testing.T) {
			d, now, _, leases := newConnectorPairPrerequisites(t)
			r := appliedProjectRequest(t, d, now)
			r.Configuration = workloadConfiguration()
			r = selectedProjectRequest(r, "production")
			applied, err := d.ApplyProjectConfiguration(t.Context(), r)
			if err != nil {
				t.Fatal(err)
			}
			exchange, key := workloadExchange(t, r, now)
			session, err := d.ExchangeWorkload(t.Context(), exchange, now)
			if err != nil {
				t.Fatal(err)
			}
			request := workloadPairRenewalRequest(t, d, r, applied.Services[0].ServiceID, session, key, leases, now)
			request.Action, request.PreviousPairID, request.PreviousGeneration = "create", "", 0
			f := connectorPairFixture{d: d, now: now, key: key, visitor: t.Context(), request: request}
			f.sign(t, &f.request)
			pair := f.create(t)
			retire := connectorRetireRequest(t, f, pair, now.Add(time.Second))
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			end := func() error {
				_, err := d.RetireConnectorPeerPair(ctx, pair.ServiceID, pair.ID, retire, retire.Proof.RequestedAt)
				return err
			}
			revoke := func() error {
				return d.RevokeWorkloadSession(ctx, session.ID, session.Credential, now.Add(time.Second))
			}
			if order == "concurrent" {
				start := make(chan struct{})
				var workers sync.WaitGroup
				results := make(chan error, 2)
				for _, work := range []func() error{end, revoke} {
					workers.Go(func() { <-start; results <- work() })
				}
				close(start)
				workers.Wait()
				close(results)
				for err := range results {
					if err != nil {
						t.Fatal("concurrent negative cleanup depended on current workload permission", err)
					}
				}
			} else {
				first, second := end, revoke
				if order == "revoke first" {
					first, second = revoke, end
				}
				if err := first(); err != nil {
					t.Fatal(err)
				}
				if err := second(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := d.RetireConnectorPeerPair(t.Context(), pair.ServiceID, pair.ID, retire, now.Add(2*time.Second)); err != nil {
				t.Fatal("revoked workload could not confirm its identical exact retirement", err)
			}
		})
	}
}
