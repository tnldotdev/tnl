package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationMachinePublicationRefreshAuthorityExpiryDuringWait(t *testing.T) {
	for _, test := range []struct{ bound, lock string }{{"source", "machine"}, {"source", "publisher"}, {"session", "machine"}, {"permission", "machine"}} {
		t.Run(test.bound+"/"+test.lock, func(t *testing.T) {
			bound := test.bound
			d, now, base, _ := newPublishRunPrerequisites(t)
			f := publicationMachine(t, d, base.TeamID, base.ActingIdentityID, "signing_key", now)
			permission, err := d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Resource: base.PublicURLID, ExpiresAt: now.Add(time.Hour)}, base.ActingIdentityID, now)
			if err != nil {
				t.Fatal(err)
			}
			exchange, key := publicationExchange(t, f, base.PublicURLID, "")
			session, err := d.ExchangeMachinePublication(t.Context(), exchange, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
			if err != nil {
				t.Fatal(err)
			}
			p, err := d.AuthenticatePublisherAccess(t.Context(), session.AccessToken, "", now)
			if err != nil {
				t.Fatal(err)
			}
			u, err := d.GetPublicURLForAuthorization(t.Context(), base.PublicURLID)
			if err != nil {
				t.Fatal(err)
			}
			r := reviewRunRequest(t, d, p, key, u, "refresh-authority-wait")
			r.ActingMachineID = p.CreatorMachineID
			run, err := d.CreatePublishRun(t.Context(), r, now, 10*time.Minute, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			deadline := session.IdentityExpiresAt
			if bound == "session" {
				deadline = now.Add(30 * time.Second)
				_, err = d.pool.Exec(t.Context(), `UPDATE control.machine_publication_sessions SET expires_at=$2 WHERE id=$1`, session.Id, deadline)
			} else if bound == "permission" {
				deadline = now.Add(30 * time.Second)
				_, err = d.pool.Exec(t.Context(), `UPDATE control.machine_publication_permissions SET expires_at=$2 WHERE id=$1`, permission.ID, deadline)
			}
			if err != nil {
				t.Fatal(err)
			}
			at := deadline.Add(-time.Second)
			encoded := base64.RawURLEncoding.EncodeToString(exchange.PublicKey)
			audience := machineTestServer + "/v1/machine-publication-sessions/" + session.Id + "/refresh"
			proof := f.publicationProof(t, u.ID, "", "refresh", encoded, session.Id, audience, at)
			signature := ed25519.Sign(key, machineproof.PublicationPossession(u.ID, "", "refresh", encoded, session.Id, sha256.Sum256([]byte(proof.Assertion))))
			saved := func() []byte {
				t.Helper()
				var value []byte
				if err := d.pool.QueryRow(t.Context(), `SELECT json_build_object(
					'session',(SELECT to_jsonb(s) FROM control.machine_publication_sessions s WHERE id=$1),
					'access',(SELECT count(*) FROM control.publisher_access_tokens WHERE publisher_identity_id=$2),
					'proofs',(SELECT count(*) FROM control.machine_proof_uses WHERE machine_id=$3),
					'run',(SELECT to_jsonb(r) FROM control.publish_runs r WHERE id=$4))::text`, session.Id, p.ID, f.machine.ID, run.PublishRunID).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := saved()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			lockQuery, lockID, expectedQuery := `SELECT id FROM control.machine_identities WHERE id=$1 FOR UPDATE`, f.machine.ID, "FOR UPDATE OF m"
			if test.lock == "publisher" {
				lockQuery, lockID, expectedQuery = `SELECT id FROM control.publisher_identities WHERE id=$1 FOR UPDATE`, p.ID, "LockPublisherIdentity"
			}
			if _, err = gate.Exec(ctx, lockQuery, lockID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			entered, done := make(chan time.Time, 1), make(chan error, 1)
			var refreshed MachinePublicationSession
			workers.Go(func() {
				entered <- time.Now()
				var err error
				refreshed, err = d.RefreshMachinePublication(ctx, session.Id, proof, signature, audience, at)
				done <- err
			})
			pid := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			var query string
			if err = d.pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&query); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(query, expectedQuery) {
				t.Fatal("refresh did not reach its expected row wait after reading the old source deadline")
			}
			started := awaitIntegrationResult(t, ctx, entered)
			// spend the original remaining authority after observing the real
			// lock wait, rather than changing its deadline while refresh runs.
			timer := time.NewTimer(deadline.Sub(at))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			releasedAt := at.Add(time.Since(started))
			if !releasedAt.After(deadline) || !releasedAt.Before(at.Add(publisherproof.AssertionLifetime)) {
				t.Fatal("row lock must cross old authority expiry while the fresh proof is valid")
			}
			if err = gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrMachineDenied) {
				t.Errorf("refresh revived authority after %s expiry during %s-row wait: %v", bound, test.lock, err)
			}
			if refreshed.Id != "" || refreshed.AccessToken != "" || !bytes.Equal(before, saved()) {
				t.Error("denied refresh changed session, access tokens, replay records or publish run")
			}
			auth := PublishRunAuthentication{PublicURLID: u.ID, PublishRunID: run.PublishRunID, PublishRunNumber: run.PublishRunNumber, PublishRunToken: run.PublishRunToken}
			if _, err = d.HeartbeatPublishRun(ctx, auth, releasedAt, time.Minute, time.Minute); !errors.Is(err, ErrPublisherIdentity) && !errors.Is(err, ErrPublishRunStale) {
				t.Error("expired authority renewed the existing run", err)
			}
		})
	}
}

func TestIntegrationMachinePublicationExchangeRetryAuthorityExpiryDuringWait(t *testing.T) {
	for _, bound := range []string{"source", "session", "permission"} {
		t.Run(bound+"/publisher", func(t *testing.T) {
			d, now, base, _ := newPublishRunPrerequisites(t)
			f := publicationMachine(t, d, base.TeamID, base.ActingIdentityID, "signing_key", now)
			permission, err := d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Resource: base.PublicURLID, ExpiresAt: now.Add(time.Hour)}, base.ActingIdentityID, now)
			if err != nil {
				t.Fatal(err)
			}
			exchange, key := publicationExchange(t, f, base.PublicURLID, "")
			audience := machineTestServer + "/v1/machine-publication-sessions/exchange"
			session, err := d.ExchangeMachinePublication(t.Context(), exchange, audience, now)
			if err != nil {
				t.Fatal(err)
			}
			p, err := d.AuthenticatePublisherAccess(t.Context(), session.AccessToken, "", now)
			if err != nil {
				t.Fatal(err)
			}
			u, err := d.GetPublicURLForAuthorization(t.Context(), base.PublicURLID)
			if err != nil {
				t.Fatal(err)
			}
			r := reviewRunRequest(t, d, p, key, u, "exchange-retry-authority-wait")
			r.ActingMachineID = p.CreatorMachineID
			run, err := d.CreatePublishRun(t.Context(), r, now, 10*time.Minute, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			deadline := session.IdentityExpiresAt
			if bound == "session" {
				deadline = now.Add(30 * time.Second)
				_, err = d.pool.Exec(t.Context(), `UPDATE control.machine_publication_sessions SET expires_at=$2 WHERE id=$1`, session.Id, deadline)
			} else if bound == "permission" {
				deadline = now.Add(30 * time.Second)
				_, err = d.pool.Exec(t.Context(), `UPDATE control.machine_publication_permissions SET expires_at=$2 WHERE id=$1`, permission.ID, deadline)
			}
			if err != nil {
				t.Fatal(err)
			}
			at := deadline.Add(-time.Second)
			encoded := base64.RawURLEncoding.EncodeToString(exchange.PublicKey)
			// only proof bytes change: the original nonce and native key select
			// the persisted session instead of issuing another publisher.
			exchange.Proof = f.publicationProof(t, u.ID, "", "exchange", encoded, exchange.Nonce, audience, at)
			exchange.Signature = ed25519.Sign(key, machineproof.PublicationPossession(u.ID, "", "exchange", encoded, exchange.Nonce, sha256.Sum256([]byte(exchange.Proof.Assertion))))
			saved := func() []byte {
				t.Helper()
				var value []byte
				if err := d.pool.QueryRow(t.Context(), `SELECT json_build_object(
					'session',(SELECT to_jsonb(s) FROM control.machine_publication_sessions s WHERE id=$1),
					'access',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.access_token_digest) FROM control.publisher_access_tokens a WHERE publisher_identity_id=$2),
					'proofs',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.proof_digest) FROM control.machine_proof_uses p WHERE machine_id=$3),
					'run',(SELECT to_jsonb(r) FROM control.publish_runs r WHERE id=$4))::text`, session.Id, p.ID, f.machine.ID, run.PublishRunID).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := saved()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err = gate.Exec(ctx, `SELECT id FROM control.publisher_identities WHERE id=$1 FOR UPDATE`, p.ID); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			entered, done := make(chan time.Time, 1), make(chan error, 1)
			var replayed MachinePublicationSession
			workers.Go(func() {
				entered <- time.Now()
				var err error
				replayed, err = d.ExchangeMachinePublication(ctx, exchange, audience, at)
				done <- err
			})
			pid := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			var query string
			if err = d.pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&query); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(query, "LockPublisherIdentity") {
				t.Fatal("exchange retry did not reach issuance's publisher-row wait")
			}
			started := awaitIntegrationResult(t, ctx, entered)
			// exhaust the old session's remaining authority only after observing
			// issuance blocked on the publisher. the fresh proof stays valid.
			timer := time.NewTimer(deadline.Sub(at))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			releasedAt := at.Add(time.Since(started))
			if !releasedAt.After(deadline) || !releasedAt.Before(at.Add(publisherproof.AssertionLifetime)) {
				t.Fatal("publisher wait must cross old authority expiry while the fresh exchange proof is valid")
			}
			if err = gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrMachineDenied) {
				t.Errorf("exchange retry committed after %s expiry during publisher-row wait: %v", bound, err)
			}
			if !reflect.DeepEqual(replayed, MachinePublicationSession{}) {
				t.Error("denied exchange retry returned credentials or session facts")
			}
			if !bytes.Equal(before, saved()) {
				t.Error("denied exchange retry changed session, access tokens, replay records or publish run")
			}
		})
	}
}

func TestIntegrationMachinePublicationRuntimeCurrentAuthority(t *testing.T) {
	for _, change := range []string{"permission", "identity", "rotation", "proof-expiry", "session-expiry", "permission-expiry"} {
		t.Run(change, func(t *testing.T) {
			d, now, base, _ := newPublishRunPrerequisites(t)
			f := publicationMachine(t, d, base.TeamID, base.ActingIdentityID, "signing_key", now)
			permission, err := d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Resource: base.PublicURLID, ExpiresAt: now.Add(time.Hour)}, base.ActingIdentityID, now)
			if err != nil {
				t.Fatal(err)
			}
			exchange, key := publicationExchange(t, f, base.PublicURLID, "")
			session, err := d.ExchangeMachinePublication(t.Context(), exchange, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
			if err != nil {
				t.Fatal(err)
			}
			request := func(action string, epoch int64) PublisherRuntimeRequest {
				t.Helper()
				r := PublisherRuntimeRequest{PublisherIdentityID: session.Publisher.ClientId, ScopeID: session.Publisher.GrantId, ProcessRunID: strings.Repeat("a", 32), Action: action, ExpectedEpoch: epoch, Audience: machineTestServer + "/v1/publisher-runtime", Now: now}
				var err error
				r.Assertion, err = publisherproof.Sign(r.PublisherIdentityID, session.Publisher.KeyId, publisherproof.RuntimeScope(r.ScopeID, action, r.ProcessRunID, epoch, ""), r.Audience, key, now)
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
			if _, err = d.PublisherRuntime(t.Context(), request("start", 0)); err != nil {
				t.Fatal(err)
			}
			if _, err = d.PublisherRuntime(t.Context(), request("renew", 1)); err != nil {
				t.Fatal(err)
			}
			listed := func() *PublisherRuntimeStatus {
				t.Helper()
				page, err := d.ListPublisherIdentities(t.Context(), base.TeamID, "")
				if err != nil || len(page.Identities) != 1 || page.Identities[0].Runtime == nil {
					t.Fatal("missing publisher runtime listing", err)
				}
				return page.Identities[0].Runtime
			}
			before := listed()
			if !before.Active || !before.LeaseExpiresAt.After(time.Now()) {
				t.Fatal("runtime not active before source authority loss")
			}
			switch change {
			case "permission":
				err = d.RevokeMachinePublicationPermission(t.Context(), base.TeamID, permission.ID, base.ActingIdentityID, now)
			case "identity":
				err = d.RevokeMachineIdentity(t.Context(), base.TeamID, f.machine.ID, base.ActingIdentityID, now)
			case "rotation":
				public, _, e := ed25519.GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				err = d.RotateMachineIdentityKey(t.Context(), base.TeamID, f.machine.ID, base.ActingIdentityID, "second", public, now)
			case "proof-expiry":
				_, err = d.pool.Exec(t.Context(), `UPDATE control.machine_publication_sessions SET proof_expires_at=$2 WHERE id=$1`, session.Id, now.Add(-time.Second))
			case "session-expiry":
				_, err = d.pool.Exec(t.Context(), `UPDATE control.machine_publication_sessions SET expires_at=$2 WHERE id=$1`, session.Id, now.Add(-time.Second))
			case "permission-expiry":
				_, err = d.pool.Exec(t.Context(), `UPDATE control.machine_publication_permissions SET expires_at=$2 WHERE id=$1`, permission.ID, now.Add(-time.Second))
			}
			if err != nil {
				t.Fatal(err)
			}
			after := listed()
			before.Active = false
			if !reflect.DeepEqual(before, after) {
				t.Error("source authority loss must clear runtime liveness without changing historical evidence")
			}
			if _, err = d.AuthenticatePublisherAccess(t.Context(), session.AccessToken, "", now); !errors.Is(err, ErrPublisherIdentity) {
				t.Error("current publisher authority did not reject lost source permission", err)
			}
			if _, err = d.PublisherRuntime(t.Context(), request("renew", 1)); !errors.Is(err, ErrPublisherIdentity) {
				t.Error("runtime renewed after source authority loss", err)
			}
		})
	}
}

func TestIntegrationMachinePublicationCleanupDeletedTeam(t *testing.T) {
	d, now, base, _ := newPublishRunPrerequisites(t)
	seedControlPublicURL(t, d, now, "remaining")
	var sessions []MachinePublicationSession
	for i, suffix := range []string{"session", "remaining"} {
		f := publicationMachine(t, d, "team_"+suffix, "identity_"+suffix, "signing_key", now.Add(time.Duration(i)*time.Second))
		if _, err := d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: f.r.TeamID, Resource: "public_url_" + suffix, ExpiresAt: now.Add(time.Hour)}, f.r.ActorID, f.now); err != nil {
			t.Fatal(err)
		}
		exchange, _ := publicationExchange(t, f, "public_url_"+suffix, "")
		session, err := d.ExchangeMachinePublication(t.Context(), exchange, machineTestServer+"/v1/machine-publication-sessions/exchange", f.now)
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET deleted_at=$2 WHERE id=$1`, base.TeamID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), sessions[0].AccessToken, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("deleted team retained serving authority", err)
	}
	cleanupAt := now.Add(WorkloadHistoryRetention + time.Hour)
	for pass := range 2 {
		if _, err := d.CleanupWorkloads(t.Context(), cleanupAt, 1); err != nil {
			t.Fatalf("deleted team's oldest session blocked bounded cleanup pass %d: %v", pass+1, err)
		}
		var sessionsLeft, proofsLeft int
		if err := d.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM control.machine_publication_sessions),
			(SELECT count(*) FROM control.machine_proof_uses)`).Scan(&sessionsLeft, &proofsLeft); err != nil {
			t.Fatal(err)
		}
		if sessionsLeft != 1-pass || proofsLeft != 1-pass {
			t.Fatal("terminal team starved another session or the later proof cleanup phase", sessionsLeft, proofsLeft)
		}
		var retired bool
		if err := d.pool.QueryRow(t.Context(), `SELECT p.revoked_at IS NOT NULL
			AND NOT EXISTS(SELECT 1 FROM control.machine_publication_sessions WHERE publisher_identity_id=p.id)
			AND NOT EXISTS(SELECT 1 FROM control.publisher_access_tokens WHERE publisher_identity_id=p.id)
			FROM control.publisher_identities p WHERE p.id=$1`, sessions[pass].Publisher.ClientId).Scan(&retired); err != nil || !retired {
			t.Fatal("cleanup detached source state without retiring its publisher and credentials", retired, err)
		}
	}
}
