package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationWorkloadAuthorizationAfterLockWait(t *testing.T) {
	for _, operation := range []string{"inventory", "pair permission", "pair renewal", "session renewal"} {
		for _, change := range []string{"renewal", "revocation", "lease expiry", "fixed expiry", "clock rollback"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				d, now, _, leases := newConnectorPairPrerequisites(t)
				created := now.Add(-31 * time.Second)
				r := appliedProjectRequest(t, d, created)
				r.Configuration = workloadConfiguration()
				applied, err := d.ApplyProjectConfiguration(t.Context(), r)
				if err != nil {
					t.Fatal(err)
				}
				exchange, key := workloadExchange(t, r, created)
				session, err := d.ExchangeWorkload(t.Context(), exchange, created)
				if err != nil {
					t.Fatal(err)
				}
				var pairRequest ConnectorPeerPairRequest
				if operation == "pair renewal" {
					pairRequest = workloadPairRenewalRequest(t, d, r, applied.Services[0].ServiceID, session, key, leases, now)
				}
				gate, err := d.pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				if _, err := controlstatedb.New(gate).LockLocalTeamForMutation(t.Context(), session.TeamID); err != nil {
					t.Fatal(err)
				}
				entered := make(chan time.Time, 1)
				done, join := connectorPairWorker(t, t.Context(), func(ctx context.Context) error {
					at := time.Now()
					clock := newAuthorizationClock(at)
					entered <- at
					if operation == "inventory" {
						_, err := d.ListWorkloadServices(ctx, session.Credential, at)
						return err
					}
					if operation == "session renewal" {
						_, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, signWorkloadRenewal(session, key), at)
						return err
					}
					if operation == "pair renewal" {
						pairRequest.RequestedAt = at
						message, err := pairRequest.proof().Message()
						if err != nil {
							return err
						}
						pairRequest.Signature = ed25519.Sign(key, message)
						renewed, err := d.RenewConnectorPeerPair(ctx, testVisitorIssuer, pairRequest, at)
						if err == nil && (renewed.ExpiresAt.After(at.Add(WorkloadLease)) || renewed.ExpiresAt.After(session.ExpiresAt) ||
							renewed.VisitorPermission.Permission.ExpiresAt.After(renewed.ExpiresAt)) {
							return errors.New("coherent renewal extended the original lifetime budget")
						}
						return err
					}
					// pair authorization uses read committed and this exact source reader.
					tx, err := d.pool.Begin(ctx)
					if err != nil {
						return err
					}
					defer tx.Rollback(ctx)
					authority, err := d.visitorAuthorityForSource(ctx, tx, visitorscope.Scope{Kind: visitorscope.Service, ID: applied.Services[0].ServiceID}, WorkloadTokenSource{Credential: session.Credential}, clock)
					if err == nil && (authority.Permission.ExpiresAt.After(at.Add(visitortoken.RenewableLifetime)) || authority.Permission.ExpiresAt.After(session.ExpiresAt)) {
						return errors.New("authorization wait extended the original lifetime budget")
					}
					return err
				})
				defer join()
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
				requestAt := <-entered
				changedAt := time.Now()
				if !changedAt.After(requestAt) {
					t.Fatal("mutation did not follow authorization entry")
				}
				var query string
				switch change {
				case "renewal", "clock rollback":
					if change == "clock rollback" {
						changedAt = changedAt.Add(30 * time.Second)
					}
					query = `UPDATE control.workload_sessions SET renewal_sequence=renewal_sequence+1,renewed_at=$2,lease_expires_at=LEAST($2::timestamptz+interval '90 seconds',expires_at) WHERE id=$1`
				case "revocation":
					query = `UPDATE control.workload_sessions SET revoked_at=$2 WHERE id=$1`
				case "lease expiry":
					query = `UPDATE control.workload_sessions SET lease_expires_at=$2 WHERE id=$1`
				case "fixed expiry":
					query = `UPDATE control.workload_sessions SET expires_at=$2,lease_expires_at=$2 WHERE id=$1`
				}
				if _, err := gate.Exec(ctx, query, session.ID, changedAt); err != nil {
					t.Fatal(err)
				}
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				err = awaitIntegrationResult(t, ctx, done)
				if change == "renewal" {
					if err != nil {
						t.Fatal("concurrent renewal rejected a current workload", err)
					}
					if operation == "session renewal" {
						// a blocked retry observes the later committed lease, but
						// must not independently renew it or advance its counter.
						var renewed, deadline time.Time
						var sequence int64
						if err := d.pool.QueryRow(ctx, `SELECT renewed_at,lease_expires_at,renewal_sequence FROM control.workload_sessions WHERE id=$1`, session.ID).Scan(&renewed, &deadline, &sequence); err != nil || sequence != 1 || !renewed.Equal(changedAt.Truncate(time.Microsecond)) || !deadline.Equal(changedAt.Truncate(time.Microsecond).Add(WorkloadLease)) {
							t.Fatal("blocked proof changed the concurrent committed renewal", err)
						}
					}
				} else if !errors.Is(err, ErrWorkloadDenied) {
					t.Fatal("authorization used stale source facts after a lock wait", err)
				}
			})
		}
	}
}

func TestIntegrationWorkloadRenewalProofAndIdempotence(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_renewal_proof")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first := signWorkloadRenewal(session, key)
	state := func() string {
		t.Helper()
		var saved string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_array(renewal_sequence,renewed_at,lease_expires_at,(SELECT count(*) FROM control.workload_audit WHERE workload_session_id=$1 AND event='renew'))::text FROM control.workload_sessions WHERE id=$1`, session.ID).Scan(&saved); err != nil {
			t.Fatal(err)
		}
		return saved
	}
	before := state()
	for name, proof := range map[string]WorkloadRenewal{
		"missing proof":     {},
		"wrong key":         signWorkloadRenewal(session, wrongKey),
		"other session":     {Sequence: 1, Signature: ed25519.Sign(key, workloadproof.Renew("other", 1))},
		"zero":              {Sequence: 0, Signature: ed25519.Sign(key, workloadproof.Renew(session.ID, 0))},
		"negative":          {Sequence: -1, Signature: ed25519.Sign(key, workloadproof.Renew(session.ID, -1))},
		"short signature":   {Sequence: 1, Signature: first.Signature[:63]},
		"tampered sequence": {Sequence: 2, Signature: first.Signature},
		"skipped sequence":  {Sequence: 2, Signature: ed25519.Sign(key, workloadproof.Renew(session.ID, 2))},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, proof, now.Add(31*time.Second)); !errors.Is(err, ErrWorkloadDenied) {
				t.Fatal("invalid proof renewed the lease", err)
			}
			if state() != before {
				t.Fatal("rejected proof changed renewal state")
			}
		})
	}
	var workers sync.WaitGroup
	results := make(chan WorkloadSession, 8)
	for range 8 {
		workers.Go(func() {
			renewed, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, first, now.Add(31*time.Second))
			if err != nil {
				t.Error(err)
				return
			}
			results <- renewed
		})
	}
	workers.Wait()
	close(results)
	for result := range results {
		if result.RenewalSequence != 1 || !result.LeaseExpiresAt.Equal(now.Add(121*time.Second)) || !result.ExpiresAt.Equal(session.ExpiresAt) {
			t.Fatal("concurrent proof changed lease or fixed window")
		}
		session = result
	}
	before = state()
	retry, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, first, now.Add(62*time.Second))
	if err != nil || !reflect.DeepEqual(retry, session) || state() != before {
		t.Fatal("lost-response retry extended or changed the lease", err)
	}
	next, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, signWorkloadRenewal(session, key), now.Add(63*time.Second))
	if err != nil || next.RenewalSequence != 2 || !next.LeaseExpiresAt.Equal(now.Add(153*time.Second)) {
		t.Fatal("next signed step did not renew", err)
	}
	before = state()
	if _, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, first, now.Add(64*time.Second)); !errors.Is(err, ErrWorkloadDenied) || state() != before {
		t.Fatal("old signed proof replayed after a later renewal", err)
	}
	earlyProof := signWorkloadRenewal(next, key)
	early, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, earlyProof, now.Add(64*time.Second))
	if err != nil || early.RenewalSequence != 3 || !early.LeaseExpiresAt.Equal(next.LeaseExpiresAt) || !early.RenewAfter.Equal(next.RenewAfter) {
		t.Fatal("early proof extended the lease", err)
	}
	before = state()
	if retried, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, earlyProof, now.Add(95*time.Second)); err != nil || !reflect.DeepEqual(retried, early) || state() != before {
		t.Fatal("early proof became a fresh renewal on retry", err)
	}
	if _, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, earlyProof, early.LeaseExpiresAt); !errors.Is(err, ErrWorkloadDenied) || state() != before {
		t.Fatal("idempotent proof resurrected an expired lease", err)
	}
	var audits int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.workload_audit WHERE workload_session_id=$1 AND event='renew'`, session.ID).Scan(&audits); err != nil || audits != 3 {
		t.Fatal("retries duplicated renewal audit", audits, err)
	}
}

func TestIntegrationWorkloadRenewalSequenceLimit(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_renewal_limit")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.workload_sessions SET renewal_sequence=-1 WHERE id=$1`, session.ID); err == nil {
		t.Fatal("schema accepted negative sequence")
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.workload_sessions SET renewal_sequence=$2 WHERE id=$1`, session.ID, int64(math.MaxInt64-1)); err != nil {
		t.Fatal(err)
	}
	session.RenewalSequence = math.MaxInt64 - 1
	proof := signWorkloadRenewal(session, key)
	last, err := d.RenewWorkloadSession(t.Context(), session.ID, session.Credential, proof, now.Add(31*time.Second))
	if err != nil || last.RenewalSequence != math.MaxInt64 {
		t.Fatal("last sequence failed", err)
	}
	if retry, err := d.RenewWorkloadSession(t.Context(), session.ID, session.Credential, proof, now.Add(62*time.Second)); err != nil || !reflect.DeepEqual(last, retry) {
		t.Fatal("last sequence retry changed lease", err)
	}
	for _, sequence := range []int64{math.MinInt64, 0, math.MaxInt64 - 1} {
		proof := WorkloadRenewal{Sequence: sequence, Signature: ed25519.Sign(key, workloadproof.Renew(session.ID, sequence))}
		if _, err := d.RenewWorkloadSession(t.Context(), session.ID, session.Credential, proof, now.Add(63*time.Second)); !errors.Is(err, ErrWorkloadDenied) {
			t.Fatal("sequence limit wrapped or accepted stale proof", err)
		}
	}
}

func workloadPairRenewalRequest(t *testing.T, d *Database, r ApplyProjectConfigurationRequest, service string, session WorkloadSession, key ed25519.PrivateKey, leases map[string]RelayLease, now time.Time) ConnectorPeerPairRequest {
	t.Helper()
	ctx := t.Context()
	enrollment, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, enrollment, now)
	var assignment PublisherGroupServiceAssignment
	for _, candidate := range replica.assignments.Services {
		if candidate.ServiceID == service {
			assignment = candidate
		}
	}
	access := groupAssignmentAccess(t, d, replica, assignment, now)
	prepared, err := d.PrepareServiceRun(ctx, service, access.PublisherIdentity, "renewal-wait", now,
		ServiceMetadata{Protocol: assignment.Configuration.Protocol, PublisherPool: true, TrustRevision: assignment.TrustRevision})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, prepared, run, now)
	for _, slot := range run.Connections {
		lease := leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, service, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.HeartbeatServiceRun(ctx, service, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	f := connectorPairFixture{d: d, now: now, visitor: ctx, key: key, request: ConnectorPeerPairRequest{
		ServiceID: service, ServiceRunID: run.RunID, RunNumber: run.RunNumber, PublisherIdentityID: access.PublisherIdentity.ID,
		Subject: session.Subject, Source: WorkloadTokenSource{Credential: session.Credential}, IdempotencyKey: "renewal-wait",
		Action: "create", RequestedAt: now, ExpectedRelays: testConnectorPairRelays(run, leases),
	}}
	f.sign(t, &f.request)
	pair := f.create(t)
	if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	f.request.Action, f.request.PreviousPairID, f.request.PreviousGeneration = "renew", pair.ID, pair.DeliveryGeneration
	return f.request
}

func TestIntegrationWorkloadRenewalOverlapsObservation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_renewal_observation")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	service := applied.Services[0].ServiceID
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service}
	// the request captures its clock before a renewal commits, but establishes
	// its database snapshot afterward. no scheduler or real lease wait is needed.
	observed := now.Add(31 * time.Second)
	readPolicy := func(t *testing.T, after int64, at time.Time) controlv1.VisitorPolicyUpdate {
		t.Helper()
		tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		update, err := d.readVisitorPolicy(ctx, tx, scope, after, at)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return update
	}
	lease, err := visitorlease.New(scope, func() time.Time { return observed })
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	apply := func(t *testing.T, wire controlv1.VisitorPolicyUpdate) {
		t.Helper()
		update, err := visitorlease.Decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
	}
	apply(t, readPolicy(t, 0, observed))
	view, _, _ := lease.Current()
	issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, WorkloadTokenSource{Credential: session.Credential}, observed)
	if err != nil {
		t.Fatal(err)
	}
	entry := tunnelv1.ConnectorPeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorPeerVisitorStream,
		PairID: mustOpaqueID(t, "cpp_"), DeliveryID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), DeliveryGeneration: 1,
		ServiceID: service, ServiceRunID: mustOpaqueID(t, opaqueid.ServiceRunPrefix), RunNumber: 1, Subject: session.Subject,
		SourceIP: "192.0.2.1", VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), MetadataRevision: uint64(view.MetadataRevision),
		Permission: tunnelv1.ConnectorVisitorPermission{Token: issued.Token.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(exchange.PublicKey), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}}
	message, err := tunnelv1.ConnectorPeerProofMessage(entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	expected := entry.Session()
	expected.ExpiresAt = session.LeaseExpiresAt
	permission, err := visitortoken.VerifyConnectorPeerSession(entry, nil, expected, view, observed)
	if err != nil {
		t.Fatal(err)
	}
	var stopped atomic.Int32
	guard, err := lease.BindConnector(permission, netip.MustParseAddr(entry.SourceIP), int64(entry.MetadataRevision), func() { stopped.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := guard.AllowRenewal(); err != nil {
		t.Fatal(err)
	}
	renewed, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, signWorkloadRenewal(session, key), observed.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("publisher policy", func(t *testing.T) {
		update := readPolicy(t, view.VisitorPolicyRevision, observed)
		apply(t, update)
		if _, err := guard.Current(); err != nil || stopped.Load() != 0 {
			t.Error("concurrent renewal canceled the retained connector stream guard", err)
		}
		if len(update.Policy.WorkloadLeases) != 1 || update.Policy.WorkloadLeases[0].SessionId != session.ID {
			t.Fatal("concurrent renewal disappeared from a successful policy observation")
		}
		if update.Policy.WorkloadLeases[0].ExpiresAt.After(observed.Add(WorkloadLease)) {
			t.Fatal("policy observation borrowed time after its request clock")
		}
	})
	t.Run("source clock and lifetime fences", func(t *testing.T) {
		// a rollback stays behind the source even after the authorization work;
		// a millisecond-wide gap can legitimately elapse during database reads.
		for _, at := range []time.Time{now.Add(-time.Second), observed.Add(-time.Second), renewed.LeaseExpiresAt, session.ExpiresAt} {
			if _, err := d.ListWorkloadServices(ctx, session.Credential, at); !errors.Is(err, ErrWorkloadDenied) {
				t.Error("invalid lifetime accepted a workload credential", err)
			}
		}
	})
	t.Run("revocation", func(t *testing.T) {
		if err := d.RevokeWorkloadSession(ctx, session.ID, session.Credential, observed.Add(2*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, WorkloadTokenSource{Credential: session.Credential}, observed.Add(3*time.Millisecond)); !errors.Is(err, ErrWorkloadDenied) {
			t.Fatal("in-flight request ignored committed revocation", err)
		}
		apply(t, readPolicy(t, 0, observed))
		if _, err := guard.Current(); err == nil || stopped.Load() != 1 {
			t.Fatal("committed revocation did not stop the retained connector stream guard", err)
		}
	})
}
