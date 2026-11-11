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

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
)

func TestIntegrationMachineWorkloadProofBindsExactGroup(t *testing.T) {
	f := newMachineFixture(t, "signing_key")
	ctx := t.Context()
	current, err := f.d.GetProjectConfiguration(ctx, f.r.TeamID, f.r.ProjectKey, f.r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	current, err = f.d.CreatePublisherGroup(ctx, f.r.TeamID, f.r.ProjectKey, "two", "production", f.r.ActorID, current.Revision, false, f.now)
	if err != nil {
		t.Fatal(err)
	}
	var groupB, serviceA, serviceB string
	for _, group := range current.Groups {
		if group.Name == "two" {
			groupB = group.ID
		}
	}
	for _, service := range current.Services {
		if service.Service == "api" {
			if service.PublisherGroup == "one" {
				serviceA = service.ServiceID
			}
			if service.PublisherGroup == "two" {
				serviceB = service.ServiceID
			}
		}
	}
	if groupB == "" || serviceA == "" || serviceB == "" || serviceA == serviceB {
		t.Fatal("missing independently realized same-template groups")
	}
	// both groups are approved by the same permission: rejection below must
	// come from proof scope, not a missing template or nonexistent resource.
	if _, err = f.d.CreateMachineWorkloadPermission(ctx, MachineWorkloadPermission{MachineID: f.machine.ID, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Workload: "test", Templates: []string{"production"}, ExpiresAt: f.now.Add(time.Hour)}, f.r.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	sign := func(group, operation, public, nonce string, services []string, audience string) MachineProof {
		t.Helper()
		scope := machineproof.Workload(group, "test", operation, public, nonce, services)
		raw, e := publisherproof.Sign(f.machine.ID, "first", scope, audience, f.key, f.now)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = publisherproof.Verify(raw, f.machine.ID, "first", scope, audience, f.key.Public().(ed25519.PublicKey), f.now); e != nil {
			t.Fatal("fixture machine signature was invalid", e)
		}
		return MachineProof{Assertion: raw}
	}
	resolveAudience := machineTestServer + "/v1/publisher-groups/" + groupB + "/resolve"
	for _, test := range []struct{ group, operation string }{{f.group, "resolve"}, {groupB, "exchange"}} {
		proof := MachineWorkloadProof{MachineID: f.machine.ID, GroupID: groupB, Audience: resolveAudience, Proof: sign(test.group, test.operation, "", "", nil, resolveAudience)}
		if _, err = f.d.ResolvePublisherGroupWorkload(ctx, groupB, "test", machineTestServer, oidc.WorkloadExecution{}, &proof, f.now); !errors.Is(err, ErrMachineDenied) {
			t.Fatal("resolution accepted another group or operation's valid proof", err)
		}
	}
	proofB := MachineWorkloadProof{MachineID: f.machine.ID, GroupID: groupB, Audience: resolveAudience, Proof: sign(groupB, "resolve", "", "", nil, resolveAudience)}
	resolved, err := f.d.ResolvePublisherGroupWorkload(ctx, groupB, "test", machineTestServer, oidc.WorkloadExecution{}, &proofB, f.now)
	if err != nil || resolved.Connection.GroupId != groupB {
		t.Fatal("otherwise approved group could not resolve", err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(public)
	audience := machineTestServer + "/v1/machine-workload-sessions/exchange"
	exchange := func(signedGroup, bodyGroup, nonce string, services []string) (ExchangeWorkloadRequest, MachineWorkloadProof) {
		t.Helper()
		machine := MachineWorkloadProof{MachineID: f.machine.ID, GroupID: bodyGroup, Audience: audience, Proof: sign(signedGroup, "exchange", encoded, nonce, services, audience)}
		digest := sha256.Sum256([]byte(machine.Proof.Assertion))
		r := ExchangeWorkloadRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, SourceFingerprint: f.r.SourceFingerprint, Workload: "test", Nonce: nonce, PublicKey: public, Services: services}
		message := workloadproof.Exchange(r.TeamID, r.ProjectKey, r.Workload, r.SourceFingerprint, nonce, digest, services)
		r.Signature = ed25519.Sign(key, message)
		if !ed25519.Verify(public, message, r.Signature) {
			t.Fatal("fixture ephemeral signature was invalid")
		}
		return r, machine
	}
	nonceA := rand.Text()
	r, machine := exchange(f.group, f.group, nonceA, []string{f.group + "/api"})
	session, err := f.d.ExchangeMachineWorkload(ctx, r, machine, f.now)
	if err != nil || !reflect.DeepEqual(session.ServiceIDs, []string{serviceA}) {
		t.Fatal("initial exact-group session", err)
	}
	facts := func() []byte {
		t.Helper()
		var value []byte
		if e := f.d.pool.QueryRow(ctx, `SELECT jsonb_build_object('sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) FROM control.workload_sessions s),'rights',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.workload_session_id,r.service_id) FROM control.workload_session_services r),'machines',(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.session_id) FROM control.workload_session_machines m),'proofs',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.machine_id,p.proof_digest) FROM control.machine_proof_uses p))::text`).Scan(&value); e != nil {
			t.Fatal(e)
		}
		return value
	}
	before := facts()
	nonceB := rand.Text()
	for _, test := range []struct{ bodyGroup, nonce string }{{groupB, nonceB}, {groupB, nonceA}, {f.group, rand.Text()}} {
		// both signatures cover the exact B service, ephemeral key and nonce.
		// only the asserted group differs from the body/selected service group.
		r, machine = exchange(f.group, test.bodyGroup, test.nonce, []string{groupB + "/api"})
		if _, err = f.d.ExchangeMachineWorkload(ctx, r, machine, f.now); !errors.Is(err, ErrMachineDenied) {
			t.Fatal("exchange accepted proof A for group/service B", err)
		}
		if !bytes.Equal(before, facts()) {
			t.Fatal("denied exchange created a session, widened rights or consumed a proof")
		}
	}
	services, err := f.d.ListWorkloadServices(ctx, session.Credential, f.now)
	if err != nil || len(services) != 1 || services[0].ID != serviceA {
		t.Fatal("original session widened", err)
	}
	if _, err = f.d.CheckWorkloadService(ctx, session.Credential, serviceB, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("original credential reached group B", err)
	}
	// the rejected new nonce remains usable with the correctly scoped proof.
	r, machine = exchange(groupB, groupB, nonceB, []string{groupB + "/api"})
	second, err := f.d.ExchangeMachineWorkload(ctx, r, machine, f.now)
	if err != nil || second.ID == session.ID || !reflect.DeepEqual(second.ServiceIDs, []string{serviceB}) {
		t.Fatal("correct B proof did not create a separate exact session", err)
	}
}
