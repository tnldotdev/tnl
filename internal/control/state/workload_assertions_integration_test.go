package controlstate

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/workloadproof"
)

func TestIntegrationWorkloadAssertionAttachment(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_attach")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	rotated := exchange
	g := *exchange.Execution.GitHub
	g.JTI = "rotated"
	rotated.Execution.GitHub = &g
	signWorkloadRequest(&rotated, key)
	binding, err := d.IdentifyWorkload(t.Context(), r.TeamID, r.ProjectKey, "test", r.SourceFingerprint, rotated.Execution, now)
	if err != nil || binding != session.Binding {
		t.Fatal("rotating assertion changed verified identity", err)
	}
	signature := ed25519.Sign(key, workloadproof.Attach(session.ID, rotated.Execution.AssertionDigest))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			next, err := d.AttachWorkloadAssertion(t.Context(), session.ID, session.Credential, rotated.Execution, signature, now)
			if err != nil || next.ID != session.ID || next.Binding != session.Binding || !next.ExpiresAt.Equal(session.ExpiresAt) || len(next.ServiceIDs) != 2 {
				t.Error("retry-stable attachment changed session rights/window", err)
			}
		})
	}
	wg.Wait()
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := d.AttachWorkloadAssertion(t.Context(), session.ID, session.Credential, rotated.Execution, ed25519.Sign(wrong, workloadproof.Attach(session.ID, rotated.Execution.AssertionDigest)), now); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("attachment accepted another key", err)
	}
	for _, field := range []string{"repository_id", "repository_owner_id", "run_id", "run_attempt", "check_run_id"} {
		foreign := rotated
		g := *rotated.Execution.GitHub
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
		foreign.Execution.GitHub = &g
		signWorkloadRequest(&foreign, key)
		if _, err := d.AttachWorkloadAssertion(t.Context(), session.ID, session.Credential, foreign.Execution, ed25519.Sign(key, workloadproof.Attach(session.ID, foreign.Execution.AssertionDigest)), now); !errors.Is(err, ErrWorkloadDenied) {
			t.Fatal("attachment changed immutable execution", field, err)
		}
	}
	// a different execution cannot consume an already-bound JTI, even with its
	// own valid key and an otherwise matching policy.
	foreign, foreignKey := workloadExchange(t, r, now)
	foreign.Execution.GitHub.CheckRunID = "333"
	foreign.Execution.GitHub.JTI = "rotated"
	signWorkloadRequest(&foreign, foreignKey)
	if _, err := d.ExchangeWorkload(t.Context(), foreign, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("JTI crossed execution boundary", err)
	}
	// narrowing one service and duration leaves the other service usable; later
	// additions cannot expand this session's issued snapshot.
	r.ExpectedRevision = applied.Revision
	p := r.Configuration.Workloads["test"]
	p.Services, p.MaxDurationSeconds = []string{"db"}, 120
	r.Configuration.Workloads["test"] = p
	applied, err = d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	next, err := d.AttachWorkloadAssertion(t.Context(), session.ID, session.Credential, rotated.Execution, signature, now)
	if err != nil || len(next.ServiceIDs) != 1 || !next.ExpiresAt.Equal(now.Add(120*time.Second)) {
		t.Fatal("attachment did not preserve narrowed rights/deadline", err)
	}
	if _, err := d.CheckWorkloadService(t.Context(), session.Credential, next.ServiceIDs[0], now); err != nil {
		t.Fatal("unaffected service lost authorization", err)
	}
	r.ExpectedRevision = applied.Revision
	p.Services = []string{"api", "db"}
	r.Configuration.Workloads["test"] = p
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	next, err = d.AttachWorkloadAssertion(t.Context(), session.ID, session.Credential, rotated.Execution, signature, now)
	if err != nil || len(next.ServiceIDs) != 1 {
		t.Fatal("attachment expanded issued snapshot", err)
	}
	late := rotated
	g = *rotated.Execution.GitHub
	g.IssuedAt, g.NotBefore, g.ExpiresAt = now.Add(130*time.Second).Unix(), now.Add(130*time.Second).Unix(), now.Add(4*time.Minute).Unix()
	late.Execution.GitHub = &g
	late.Execution.IssuedAt, late.Execution.NotBefore, late.Execution.ExpiresAt = g.IssuedAt, g.NotBefore, g.ExpiresAt
	signWorkloadRequest(&late, key)
	lateSignature := ed25519.Sign(key, workloadproof.Attach(session.ID, late.Execution.AssertionDigest))
	if _, err := d.AttachWorkloadAssertion(t.Context(), session.ID, session.Credential, late.Execution, lateSignature, now.Add(130*time.Second)); !errors.Is(err, ErrWorkloadExpired) {
		t.Fatal("narrowed expiry was not distinguished from authorization denial", err)
	}
	for range 2 {
		if err := d.RevokeWorkloadSession(t.Context(), session.ID, session.Credential, now.Add(time.Hour)); err != nil {
			t.Fatal("expired/revoked stop is not idempotent", err)
		}
	}
	if _, err := d.AttachWorkloadAssertion(t.Context(), session.ID, session.Credential, late.Execution, lateSignature, now.Add(130*time.Second)); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("revoked session authorized replacement", err)
	}
}
