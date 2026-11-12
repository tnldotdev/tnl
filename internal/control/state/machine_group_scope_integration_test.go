package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationMachineWorkloadProofBindsExactGroup(t *testing.T) {
	f := newMachineFixture(t, "signing_key")
	ctx := t.Context()
	second, err := f.d.CreateEnvironment(ctx, CreateEnvironmentRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, ActorID: f.r.ActorID, SourceFingerprint: f.r.SourceFingerprint, Name: "two", CollectionID: f.collection.ID, ExpectedCollectionRevision: f.collection.MutationRevision, Targets: EnvironmentTargets{"api": {Address: "api-b.internal:3000"}, "db": {Address: "db-b.internal:5432"}}, IdempotencyKey: "machine-two", Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	var serviceA, serviceB string
	for _, service := range f.environment.Services {
		if service.Service == "api" {
			serviceA = service.ServiceID
		}
	}
	for _, service := range second.Services {
		if service.Service == "api" {
			serviceB = service.ServiceID
		}
	}
	if serviceA == "" || serviceB == "" || serviceA == serviceB {
		t.Fatal("same definition shared environment service IDs")
	}
	// both saved environments are explicitly approved. rejection must come from
	// proof scope, not a missing resource or an unapproved environment.
	permission, err := f.d.CreateEnvironmentVisitorPermission(ctx, EnvironmentVisitorPermission{MachineID: f.machine.ID, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Scope: EnvironmentPermissionScope{EnvironmentIDs: []string{f.environment.ID, second.ID}}, Services: []string{"api", "db"}, MaxDurationSeconds: 3600, ExpiresAt: f.now.Add(time.Hour)}, f.r.ActorID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(public)
	const audience = machineTestServer + "/v1/environment-visitor-sessions/prepare"
	request := func(signed, body, operation, nonce string, services map[string]string) PrepareEnvironmentVisitorRequest {
		t.Helper()
		scope := machineproof.EnvironmentVisitor(permission.ID, signed, operation, encoded, nonce, services)
		raw, err := publisherproof.Sign(f.machine.ID, "first", scope, audience, f.key, f.now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publisherproof.Verify(raw, f.machine.ID, "first", scope, audience, f.key.Public().(ed25519.PublicKey), f.now); err != nil {
			t.Fatal("invalid fixture machine signature", err)
		}
		r := PrepareEnvironmentVisitorRequest{ProjectKey: f.r.ProjectKey, EnvironmentID: body, PermissionID: permission.ID, Audience: audience, Nonce: nonce, PublicKey: public, Services: services, Proof: MachineProof{Assertion: raw}}
		digest := sha256.Sum256([]byte(raw))
		message := machineproof.EnvironmentVisitorPossession(r.ProjectKey, permission.ID, body, "prepare", encoded, nonce, services, digest)
		r.Signature = ed25519.Sign(key, message)
		if !ed25519.Verify(public, message, r.Signature) {
			t.Fatal("invalid fixture ephemeral signature")
		}
		return r
	}
	for _, wrong := range []struct{ environment, operation string }{{f.environment.ID, "prepare"}, {second.ID, "attach"}} {
		if _, err := f.d.PrepareEnvironmentVisitor(ctx, request(wrong.environment, second.ID, wrong.operation, rand.Text(), map[string]string{"api": "http"}), f.now); !errors.Is(err, ErrMachineDenied) {
			t.Fatal("another environment/operation proof accepted", err)
		}
	}
	nonceA := rand.Text()
	first, err := f.d.PrepareEnvironmentVisitor(ctx, request(f.environment.ID, f.environment.ID, "prepare", nonceA, map[string]string{"api": "http"}), f.now)
	if err != nil || !reflect.DeepEqual(first.Session.ServiceIDs, []string{serviceA}) {
		t.Fatal("initial exact environment session", err)
	}
	facts := func() []byte {
		t.Helper()
		var data []byte
		if err := f.d.pool.QueryRow(ctx, `SELECT jsonb_build_object('sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) FROM control.workload_sessions s),'rights',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.workload_session_id,r.service_id) FROM control.workload_session_services r),'machines',(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.session_id) FROM control.workload_session_machines m),'proofs',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.machine_id,p.proof_digest) FROM control.machine_proof_uses p))::text`).Scan(&data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := facts()
	nonceB := rand.Text()
	for _, test := range []struct{ body, nonce string }{{second.ID, nonceB}, {second.ID, nonceA}} {
		if _, err := f.d.PrepareEnvironmentVisitor(ctx, request(f.environment.ID, test.body, "prepare", test.nonce, map[string]string{"api": "http"}), f.now); !errors.Is(err, ErrMachineDenied) {
			t.Fatal("proof A authorized environment B", err)
		}
		if !bytes.Equal(before, facts()) {
			t.Fatal("denied exchange created state or consumed proof")
		}
	}
	// an otherwise valid environment proof must also bind protocol and permission.
	bad := request(f.environment.ID, f.environment.ID, "prepare", rand.Text(), map[string]string{"api": "postgres"})
	if _, err := f.d.PrepareEnvironmentVisitor(ctx, bad, f.now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("protocol mismatch accepted", err)
	}
	if !bytes.Equal(before, facts()) {
		t.Fatal("denied protocol changed state")
	}
	services, err := f.d.ListWorkloadServices(ctx, first.Session.Credential, f.now)
	if err != nil || len(services) != 1 || services[0].ID != serviceA {
		t.Fatal("original session widened", err)
	}
	if _, err := f.d.CheckWorkloadService(ctx, first.Session.Credential, serviceB, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("credential A reached B", err)
	}
	last, err := f.d.PrepareEnvironmentVisitor(ctx, request(second.ID, second.ID, "prepare", nonceB, map[string]string{"api": "http"}), f.now)
	if err != nil || last.Session.ID == first.Session.ID || !reflect.DeepEqual(last.Session.ServiceIDs, []string{serviceB}) {
		t.Fatal("correct B proof failed or reused A", err)
	}
}
