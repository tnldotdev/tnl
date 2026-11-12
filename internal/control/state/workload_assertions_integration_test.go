package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestIntegrationWorkloadAssertionAttachment(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_attach")
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	r := f.project
	exchange, key := retainedVisitorPreparation(t, f, now)
	prepared, err := d.PrepareEnvironmentVisitor(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session
	rotated := exchange
	g := *exchange.Proof.Execution.GitHub
	g.JTI = "rotated"
	rotated.Proof.Execution.GitHub = &g
	signRetainedVisitorPreparation(&rotated, key)
	retry, err := d.PrepareEnvironmentVisitor(t.Context(), rotated, now)
	if err != nil || retry.Session.Binding != session.Binding {
		t.Fatal("rotating assertion changed verified identity", err)
	}
	proof, signature, audience := retainedVisitorAssertion(t, d, session, key, rotated.Proof.Execution)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			next, err := d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, now)
			if err != nil || next.ID != session.ID || next.Binding != session.Binding || !next.ExpiresAt.Equal(*session.ExpiresAt) || len(next.ServiceIDs) != 2 {
				t.Error("retry attachment changed rights/window", err)
			}
		})
	}
	wg.Wait()
	foreignPublic, wrong, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := retainedVisitorAttachmentMessage(exchange, session, proof)
	badSignature := ed25519.Sign(wrong, message)
	if !ed25519.Verify(foreignPublic, message, badSignature) || ed25519.Verify(exchange.PublicKey, message, badSignature) || !ed25519.Verify(exchange.PublicKey, message, signature) {
		t.Fatal("foreign-key fixture did not sign the unchanged attachment message")
	}
	if _, err := d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, badSignature, audience, now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("attachment accepted another key", err)
	}
	for _, field := range []string{"repository_id", "repository_owner_id", "run_id", "run_attempt", "check_run_id"} {
		foreign := rotated
		g := *rotated.Proof.Execution.GitHub
		switch field {
		case "repository_id":
			g.RepositoryID = "999"
		case "repository_owner_id":
			g.RepositoryOwnerID = "999"
		case "run_id":
			g.RunID = "999"
		case "run_attempt":
			g.RunAttempt = "999"
		case "check_run_id":
			g.CheckRunID = "999"
		}
		foreign.Proof.Execution.GitHub = &g
		foreignProof, foreignSignature, foreignAudience := retainedVisitorAssertion(t, d, session, key, foreign.Proof.Execution)
		if _, err := d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, foreignProof, foreignSignature, foreignAudience, now); !errors.Is(err, ErrMachineDenied) {
			t.Fatal("attachment changed immutable execution", field, err)
		}
	}
	foreign, foreignKey := retainedVisitorPreparation(t, f, now)
	// provider executions may admit independent sessions. the original nonce,
	// however, cannot be taken over by another execution or possession key.
	foreign.Nonce = exchange.Nonce
	foreign.Proof.Execution.GitHub.CheckRunID = "333"
	foreign.Proof.Execution.GitHub.JTI = "rotated"
	signRetainedVisitorPreparation(&foreign, foreignKey)
	if _, err := d.PrepareEnvironmentVisitor(t.Context(), foreign, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("another execution/key took over the original admitted nonce", err)
	}
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"db": {Protocol: "postgres"}})
	applied, err := d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: f.environment.ID, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"db": {Address: "db.internal:5432"}}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	// fixed deadlines are durable session facts, not editable project policy.
	// retain a narrowed deadline at that owner and prove fresh platform evidence
	// cannot widen either it or the service IDs retired by environment apply.
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.workload_sessions SET expires_at=created_at+interval '120 seconds',lease_expires_at=LEAST(lease_expires_at,created_at+interval '120 seconds') WHERE id=$1`, session.ID); err != nil {
		t.Fatal(err)
	}
	next, err := d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, now)
	if err != nil || len(next.ServiceIDs) != 1 || !next.ExpiresAt.Equal(now.Add(120*time.Second)) {
		t.Fatal("attachment lost narrowed rights/deadline", err)
	}
	if _, err := d.CheckWorkloadService(t.Context(), session.Credential, next.ServiceIDs[0], now); err != nil {
		t.Fatal("unaffected service lost authorization", err)
	}
	definition = environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "db": {Protocol: "postgres"}})
	if _, err := d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: applied.ID, ExpectedRevision: applied.MutationRevision, DefinitionRevision: definition.Revision, Targets: f.environment.Targets}, Now: now}); err != nil {
		t.Fatal(err)
	}
	next, err = d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, now)
	if err != nil || len(next.ServiceIDs) != 1 {
		t.Fatal("attachment expanded issued snapshot", err)
	}
	late := rotated.Proof.Execution
	late.GitHub = new(*late.GitHub)
	g = *late.GitHub
	g.IssuedAt, g.NotBefore, g.ExpiresAt = now.Add(130*time.Second).Unix(), now.Add(130*time.Second).Unix(), now.Add(4*time.Minute).Unix()
	late.GitHub = &g
	late.IssuedAt, late.NotBefore, late.ExpiresAt = g.IssuedAt, g.NotBefore, g.ExpiresAt
	lateProof, lateSignature, lateAudience := retainedVisitorAssertion(t, d, session, key, late)
	if _, err := d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, lateProof, lateSignature, lateAudience, now.Add(130*time.Second)); !errors.Is(err, ErrWorkloadExpired) {
		t.Fatal("narrowed expiry not distinguished from denial", err)
	}
	for range 2 {
		if err := d.RevokeEnvironmentVisitorSession(t.Context(), session.ID, session.Credential, now.Add(time.Hour)); err != nil {
			t.Fatal("expired/revoked stop not idempotent", err)
		}
	}
	if _, err := d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, lateProof, lateSignature, lateAudience, now.Add(130*time.Second)); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("revoked session authorized replacement", err)
	}
}
