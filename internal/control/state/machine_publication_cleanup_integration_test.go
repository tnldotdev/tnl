package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

type publicationCleanupFixture struct {
	d          *Database
	now        time.Time
	base       PublishRunRequest
	leases     map[string]RelayLease
	machine    machineFixture
	permission MachinePublicationPermission
	session    MachinePublicationSession
	key        ed25519.PrivateKey
	publisher  PublisherIdentity
	invocation string
	url        PublicURL
}

func newPublicationCleanupFixture(t *testing.T) publicationCleanupFixture {
	t.Helper()
	d, now, base, leases := newPublishRunPrerequisites(t)
	f := publicationMachine(t, d, base.TeamID, base.ActingIdentityID, "signing_key", now)
	permission, err := d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Namespace: "cleanup.session.example.test", DomainID: "domain_session", ExpiresAt: now.Add(time.Hour)}, base.ActingIdentityID, now)
	if err != nil {
		t.Fatal(err)
	}
	exchange, key := publicationExchange(t, f, "", permission.Namespace)
	session, err := d.ExchangeMachinePublication(t.Context(), exchange, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := d.AuthenticatePublisherAccess(t.Context(), session.AccessToken, "", now)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	u, err := d.AllocatePublisherPublicURL(t.Context(), p, invocation, "http://127.0.0.1:3000", nil, nil, now, PublisherPublicURLOptions{AccessMode: VisitorAccessRestricted})
	if err != nil {
		t.Fatal(err)
	}
	return publicationCleanupFixture{d, now, base, leases, f, permission, session, key, p, invocation, u}
}

func (f publicationCleanupFixture) cleanupAudience() string {
	return machineTestServer + "/v1/machine-publication-sessions/" + f.session.Id + "/cleanup"
}

func (f publicationCleanupFixture) cleanupAssertion(t *testing.T, at time.Time) string {
	t.Helper()
	proof, err := publisherproof.Sign(f.publisher.ID, f.session.Publisher.KeyId, machineproof.PublicationCleanup(f.session.Id, f.invocation), f.cleanupAudience(), f.key, at)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestIntegrationMachinePublicationCleanupIndependentAuthority(t *testing.T) {
	for _, change := range []string{"active", "permission", "identity", "rotation", "source-expiry", "permission-expiry", "deleted-team"} {
		t.Run(change, func(t *testing.T) {
			f := newPublicationCleanupFixture(t)
			d, now := f.d, f.now
			// dns delivery is outside the cleanup boundary; exercise real run
			// closure, ready publisher connections and ingress tombstones.
			if _, err := d.pool.Exec(t.Context(), `UPDATE control.public_urls SET dns_state='published',dns_available_at=NULL WHERE id=$1`, f.url.ID); err != nil {
				t.Fatal(err)
			}
			r := reviewRunRequest(t, d, f.publisher, f.key, f.url, "cleanup-run")
			r.ActingMachineID = f.machine.machine.ID
			run, err := d.CreatePublishRun(t.Context(), r, now, time.Minute, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			readyTestSession(t, publishRunFixture{database: d, now: now, request: r, setup: run, leases: f.leases})
			at := now
			switch change {
			case "permission":
				err = d.RevokeMachinePublicationPermission(t.Context(), f.base.TeamID, f.permission.ID, f.base.ActingIdentityID, now)
			case "identity":
				err = d.RevokeMachineIdentity(t.Context(), f.base.TeamID, f.machine.machine.ID, f.base.ActingIdentityID, now)
			case "rotation":
				public, _, e := ed25519.GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				err = d.RotateMachineIdentityKey(t.Context(), f.base.TeamID, f.machine.machine.ID, f.base.ActingIdentityID, "second", public, now)
			case "source-expiry":
				at = now.Add(2 * time.Minute)
			case "permission-expiry":
				at = now.Add(2 * time.Hour)
			case "deleted-team":
				_, err = d.pool.Exec(t.Context(), `UPDATE control.teams SET deleted_at=$2 WHERE id=$1`, f.base.TeamID, now)
			}
			if err != nil {
				t.Fatal(err)
			}
			proof := f.cleanupAssertion(t, at)
			for range 2 {
				// only the original invocation survives a lost allocation reply;
				// cleanup never receives or relies on the public URL response.
				if err = d.CleanupMachinePublication(t.Context(), f.session.Id, f.invocation, proof, f.cleanupAudience(), at); err != nil {
					t.Fatal("native-only cleanup failed after", change, err)
				}
			}
			var closed bool
			if err = d.pool.QueryRow(t.Context(), `SELECT u.lifecycle_state='deleted'
				AND NOT EXISTS(SELECT 1 FROM control.publish_runs WHERE public_url_id=u.id AND closed_at IS NULL)
				AND NOT EXISTS(SELECT 1 FROM control.publish_run_connection_slots WHERE public_url_id=u.id AND closed_at IS NULL)
				AND (SELECT event_kind='public_url_tombstone' FROM control.ingress_routing_table_events WHERE public_url_id=u.id ORDER BY id DESC LIMIT 1)
				FROM control.public_urls u WHERE u.id=$1`, f.url.ID).Scan(&closed); err != nil || !closed {
				t.Fatal("allocation removal did not atomically close runs, connections and routing", closed, err)
			}
		})
	}
}

func TestIntegrationMachinePublicationCleanupIsolation(t *testing.T) {
	f := newPublicationCleanupFixture(t)
	d, now := f.d, f.now
	otherExchange, otherKey := publicationExchange(t, f.machine, "", f.permission.Namespace)
	otherSession, err := d.ExchangeMachinePublication(t.Context(), otherExchange, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := d.AuthenticatePublisherAccess(t.Context(), otherSession.AccessToken, "", now)
	if err != nil {
		t.Fatal(err)
	}
	otherInvocation, _ := opaqueid.New(opaqueid.InvocationPrefix)
	otherURL, err := d.AllocatePublisherPublicURL(t.Context(), other, otherInvocation, "http://127.0.0.1:3001", nil, nil, now, PublisherPublicURLOptions{AccessMode: VisitorAccessRestricted})
	if err != nil {
		t.Fatal(err)
	}
	for _, attack := range []string{"native-key", "audience", "operation", "invocation", "session", "expired"} {
		t.Run(attack, func(t *testing.T) {
			session, invocation, audience, scope, key, at := f.session.Id, f.invocation, f.cleanupAudience(), machineproof.PublicationCleanup(f.session.Id, f.invocation), f.key, now
			switch attack {
			case "native-key":
				key = otherKey
			case "audience":
				audience = "https://other.example/cleanup"
			case "operation":
				scope = machineproof.Publication("", f.permission.Namespace, "refresh", "", session)
			case "invocation":
				invocation = otherInvocation
			case "session":
				session = otherSession.Id
			case "expired":
				at = now.Add(-2 * time.Minute)
			}
			proof, err := publisherproof.Sign(f.publisher.ID, f.session.Publisher.KeyId, scope, audience, key, at)
			if err != nil {
				t.Fatal(err)
			}
			if err = d.CleanupMachinePublication(t.Context(), session, invocation, proof, f.cleanupAudience(), now); !errors.Is(err, ErrMachineDenied) {
				t.Fatal("cleanup proof escaped its original scope", err)
			}
		})
	}
	// a valid signature for this session cannot select a sibling session's
	// allocation: the lookup is by all three persisted ownership fields.
	proof, err := publisherproof.Sign(f.publisher.ID, f.session.Publisher.KeyId, machineproof.PublicationCleanup(f.session.Id, otherInvocation), f.cleanupAudience(), f.key, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.CleanupMachinePublication(t.Context(), f.session.Id, otherInvocation, proof, f.cleanupAudience(), now); err != nil {
		t.Fatal("absent owned invocation must be an idempotent no-op", err)
	}
	if _, err = d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.machine.ID, TeamID: f.base.TeamID, Resource: f.base.PublicURLID, ExpiresAt: now.Add(time.Hour)}, f.base.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	savedExchange, savedKey := publicationExchange(t, f.machine, f.base.PublicURLID, "")
	savedSession, err := d.ExchangeMachinePublication(t.Context(), savedExchange, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
	if err != nil {
		t.Fatal(err)
	}
	savedAudience := machineTestServer + "/v1/machine-publication-sessions/" + savedSession.Id + "/cleanup"
	proof, err = publisherproof.Sign(savedSession.Publisher.ClientId, savedSession.Publisher.KeyId, machineproof.PublicationCleanup(savedSession.Id, f.invocation), savedAudience, savedKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.CleanupMachinePublication(t.Context(), savedSession.Id, f.invocation, proof, savedAudience, now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("saved-resource session acquired cleanup rights", err)
	}
	for _, id := range []string{f.url.ID, otherURL.ID, f.base.PublicURLID} {
		u, err := d.GetPublicURLForAuthorization(t.Context(), id)
		if err != nil || u.LifecycleState != PublicURLLifecycleEnabled {
			t.Fatal("denied or foreign cleanup changed a public URL", id, err)
		}
	}
	// current remote-group ownership remains a deletion boundary, even if an
	// operator attaches a formerly native allocation to a remote definition.
	r := environmentPublisherTestProject{TeamID: f.base.TeamID, ActorID: f.base.ActingIdentityID, ProjectKey: "cleanup", SourceFingerprint: shaFingerprint(), Now: now}
	domain := retainedFixtureDomain(t, d, r)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"remoteapp": {Protocol: "http"}})
	applied, err := d.CreateEnvironment(t.Context(), CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, SourceFingerprint: r.SourceFingerprint, Name: "remote", DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"remoteapp": {Address: "127.0.0.1:3000"}}, DomainID: domain, IdempotencyKey: "cleanup-boundary", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	var group string
	if err := d.pool.QueryRow(t.Context(), `SELECT group_id FROM control.environments WHERE id=$1`, applied.ID).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err = d.pool.Exec(t.Context(), `INSERT INTO control.applied_project_services(team_id,project_key,service,group_id,public_url_id,desired_revision) VALUES($1,'cleanup','attached',$2,$3,1)`, f.base.TeamID, group, f.url.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.CleanupMachinePublication(t.Context(), f.session.Id, f.invocation, f.cleanupAssertion(t, now), f.cleanupAudience(), now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("cleanup deleted a remote group resource", err)
	}
}

func TestIntegrationMachinePublicationCleanupRetainsOwnershipUntilRemoval(t *testing.T) {
	for _, removal := range []string{"native", "reaper"} {
		t.Run(removal, func(t *testing.T) {
			f := newPublicationCleanupFixture(t)
			d, now := f.d, f.now
			if _, err := d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.machine.ID, TeamID: f.base.TeamID, Resource: f.base.PublicURLID, ExpiresAt: now.Add(time.Hour)}, f.base.ActingIdentityID, now); err != nil {
				t.Fatal(err)
			}
			exchange, _ := publicationExchange(t, f.machine, f.base.PublicURLID, "")
			other, err := d.ExchangeMachinePublication(t.Context(), exchange, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
			if err != nil {
				t.Fatal(err)
			}
			at := now.Add(WorkloadHistoryRetention + time.Hour)
			if _, err = d.CleanupWorkloads(t.Context(), at, 1); err != nil {
				t.Fatal(err)
			}
			var retained, removed bool
			if err = d.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM control.machine_publication_sessions WHERE id=$1),NOT EXISTS(SELECT 1 FROM control.machine_publication_sessions WHERE id=$2)`, f.session.Id, other.Id).Scan(&retained, &removed); err != nil || !retained || !removed {
				t.Fatal("live allocation lost cleanup ownership or starved eligible session GC", retained, removed, err)
			}
			if removal == "native" {
				err = d.CleanupMachinePublication(t.Context(), f.session.Id, f.invocation, f.cleanupAssertion(t, at), f.cleanupAudience(), at)
			} else {
				var count int
				count, err = d.DeleteExpiredEphemeralPublicURLs(t.Context(), at)
				if count != 1 {
					t.Fatal("crash reaper did not remove expired allocation", count)
				}
			}
			if err != nil {
				t.Fatal("expired source authority blocked allocation removal", err)
			}
			if _, err = d.CleanupWorkloads(t.Context(), at, 1); err != nil {
				t.Fatal(err)
			}
			if err = d.pool.QueryRow(t.Context(), `SELECT NOT EXISTS(SELECT 1 FROM control.machine_publication_sessions WHERE id=$1)`, f.session.Id).Scan(&removed); err != nil || !removed {
				t.Fatal("removed allocation kept an unnecessary source session", removed, err)
			}
			if err = d.CleanupMachinePublication(t.Context(), f.session.Id, f.invocation, f.cleanupAssertion(t, at), f.cleanupAudience(), at); err != nil {
				t.Fatal("already-collected cleanup was not idempotent", err)
			}
		})
	}
}

func TestIntegrationMachinePublicationCleanupProofExpiryDuringWait(t *testing.T) {
	f := newPublicationCleanupFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := f.d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err = gate.Exec(ctx, `SELECT id FROM control.public_urls WHERE id=$1 FOR NO KEY UPDATE`, f.url.ID); err != nil {
		t.Fatal(err)
	}
	proof := f.cleanupAssertion(t, f.now)
	at := f.now.Add(publisherproof.AssertionLifetime - time.Second)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	entered, done := make(chan time.Time, 1), make(chan error, 1)
	workers.Go(func() {
		entered <- time.Now()
		done <- f.d.CleanupMachinePublication(ctx, f.session.Id, f.invocation, proof, f.cleanupAudience(), at)
	})
	waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
	started := awaitIntegrationResult(t, ctx, entered)
	// the full remaining signed lifetime elapses after the observed URL wait.
	timer := time.NewTimer(f.now.Add(publisherproof.AssertionLifetime).Sub(at))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !at.Add(time.Since(started)).After(f.now.Add(publisherproof.AssertionLifetime)) {
		t.Fatal("URL wait did not exhaust the cleanup proof")
	}
	if err = gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("expired native assertion removed an allocation after its URL wait", err)
	}
	u, err := f.d.GetPublicURLForAuthorization(ctx, f.url.ID)
	if err != nil || u.LifecycleState != PublicURLLifecycleEnabled || u.MutationRevision != f.url.MutationRevision {
		t.Fatal("expired cleanup committed allocation changes", err)
	}
}
