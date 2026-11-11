package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
)

const machineTestServer = "https://control.example"
const machineTestAudience = machineTestServer + "/v1/provisioning-sessions/exchange"

type machineFixture struct {
	d       *Database
	now     time.Time
	r       ApplyProjectConfigurationRequest
	machine MachineIdentity
	grant   ProvisioningGrant
	key     ed25519.PrivateKey
	proof   MachineProof
	issuer  *githubtest.Issuer
	group   string
}

func newMachineFixture(t *testing.T, kind string) machineFixture {
	t.Helper()
	d, now := newControlStateIntegrationDatabase(t, "machine_"+kind)
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	r.Configuration.PublisherGroups = map[string]ProjectPublisherGroup{"production": {Template: true}, "other": {Template: true}}
	r.Configuration.Services["otherapi"] = ProjectServiceConfiguration{PublisherGroup: "other", Target: "other.internal:3000"}
	trust := oidc.WorkloadTrust{Provider: "oidc", Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/keys", Audience: "tnl-machine", Claims: map[string]string{"sub": "machine:one"}}
	r.Configuration.Workloads = map[string]ProjectWorkload{"test": {Provider: "oidc", Trust: trust, Services: []string{"api", "db"}, MaxDurationSeconds: 3600}}
	current, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal("apply", err)
	}
	current, err = d.CreatePublisherGroup(t.Context(), r.TeamID, r.ProjectKey, "one", "production", r.ActorID, current.Revision, false, now)
	if err != nil {
		t.Fatal("create group", err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reg := RegisterMachineRequest{TeamID: r.TeamID, ActorID: r.ActorID, Name: "machine one", ProofKind: kind}
	if kind == "oidc" {
		reg.Trust = trust
	} else {
		reg.KeyID = "first"
		reg.PublicKey = public
	}
	m, err := d.RegisterMachineIdentity(t.Context(), reg, now)
	if err != nil {
		t.Fatal("register", err)
	}
	g, err := d.CreateProvisioningGrant(t.Context(), ProvisioningGrant{MachineID: m.ID, TeamID: r.TeamID, ProjectKey: r.ProjectKey, Templates: []string{"production"}, Operations: []ProvisioningOperation{ProvisioningCreate, ProvisioningRead, ProvisioningUpdate, ProvisioningEnroll, ProvisioningRevokeMember, ProvisioningRetire}, MaxEnrollmentMembers: 2, MaxEnrollmentSeconds: 600, EnrollmentBudget: 3, ExpiresAt: now.Add(time.Hour)}, r.ActorID, now)
	if err != nil {
		t.Fatal("grant", err)
	}
	f := machineFixture{d: d, now: now, r: r, machine: m, grant: g, key: key, group: current.Groups[0].ID}
	if kind == "oidc" {
		issuer := githubtest.NewKeySet(t, trust.JWKSURL)
		f.issuer = issuer
		v, err := oidc.NewWorkloadVerifier(machineTestServer, issuer.Client)
		if err != nil {
			t.Fatal(err)
		}
		raw := issuer.Sign(t, map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": "machine:one", "iat": now.Unix(), "exp": now.Add(30 * time.Minute).Unix()})
		c, err := v.Verify(t.Context(), trust, raw)
		if err != nil {
			t.Fatal(err)
		}
		f.proof = MachineProof{Assertion: raw, Execution: c}
	}
	return f
}

func (f machineFixture) provisioningProof(t *testing.T, op ProvisioningOperation) MachineProof {
	t.Helper()
	if f.machine.ProofKind == "oidc" {
		return f.proof
	}
	raw, err := publisherproof.Sign(f.machine.ID, "first", machineproof.Provisioning(f.grant.ID, string(op)), machineTestAudience, f.key, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return MachineProof{Assertion: raw}
}

func (f machineFixture) authorize(t *testing.T, token string, scope ProvisioningScope, now time.Time, commit bool) error {
	t.Helper()
	tx, err := f.d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	_, err = f.d.AuthorizeProvisioning(t.Context(), tx, token, scope, now)
	if err == nil && commit {
		err = tx.Commit(t.Context())
	}
	return err
}

func TestIntegrationMachineOIDCReusableProofCurrentAuthority(t *testing.T) {
	f := newMachineFixture(t, "oidc")
	for _, op := range []ProvisioningOperation{ProvisioningCreate, ProvisioningRead, ProvisioningEnroll, ProvisioningCreate} {
		s, err := f.d.ExchangeProvisioning(t.Context(), "", f.grant.ID, op, f.proof, machineTestAudience, f.now)
		if err != nil {
			t.Fatal("valid projected token must be reusable for current grant operations", op, err)
		}
		if !s.ExpiresAt.Equal(f.now.Add(5 * time.Minute)) {
			t.Fatal("incorrect provisioning lifetime", s)
		}
		if s.TokenType != "Bearer" || s.TeamID != f.r.TeamID || s.ProjectKey != f.r.ProjectKey || !reflect.DeepEqual(s.Templates, []string{"production"}) || s.ProjectRevision != 2 || s.SourceFingerprint != f.r.SourceFingerprint {
			t.Fatal("missing authoritative provisioning scope", s)
		}
		scope := ProvisioningScope{Operation: op, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Template: "production", GroupID: f.group, EnrollmentMembers: 1, EnrollmentLifetime: time.Minute}
		if err = f.authorize(t, s.Credential, scope, f.now, false); err != nil {
			t.Fatal(err)
		}
		if _, err = f.d.AuthenticateAccessToken(t.Context(), credentials.AccessToken(s.Credential), f.now); err == nil {
			t.Fatal("provisioning token became person session")
		}
		if _, err = f.d.ListWorkloadServices(t.Context(), s.Credential, f.now); err == nil {
			t.Fatal("provisioning token became visitor credential")
		}
	}
	nearExpiry := f.now.Add(30*time.Minute - 10*time.Second)
	s, err := f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, ProvisioningRead, f.proof, machineTestAudience, nearExpiry)
	if err != nil || s.ExpiresAt.Unix() != f.proof.Execution.ExpiresAt {
		t.Fatal("provisioning token exceeded assertion expiry", s, err)
	}
	if _, err = f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, ProvisioningRead, f.proof, machineTestAudience, time.Unix(f.proof.Execution.ExpiresAt, 0)); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("expired platform proof accepted", err)
	}
	if err := f.d.RevokeProvisioningGrant(t.Context(), f.r.TeamID, f.grant.ID, f.r.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.ExchangeProvisioning(t.Context(), "", f.grant.ID, ProvisioningCreate, f.proof, machineTestAudience, f.now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("reused OIDC proof bypassed current revocation", err)
	}
}

func TestIntegrationMachineSignedProofReplayAndScope(t *testing.T) {
	f := newMachineFixture(t, "signing_key")
	proof := f.provisioningProof(t, ProvisioningCreate)
	for _, test := range []struct {
		name, machine, grant, audience string
		op                             ProvisioningOperation
	}{
		{"audience", f.machine.ID, f.grant.ID, "https://other.example", ProvisioningCreate},
		{"identity", "mci_unknown", f.grant.ID, machineTestAudience, ProvisioningCreate},
		{"grant", f.machine.ID, "mpg_unknown", machineTestAudience, ProvisioningCreate},
		{"operation", f.machine.ID, f.grant.ID, machineTestAudience, ProvisioningEnroll},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := f.d.ExchangeProvisioning(t.Context(), test.machine, test.grant, test.op, proof, test.audience, f.now); !errors.Is(err, ErrMachineDenied) {
				t.Fatal("wrong proof scope accepted", err)
			}
		})
	}
	s, err := f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, ProvisioningCreate, proof, machineTestAudience, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, ProvisioningCreate, proof, machineTestAudience, f.now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("signed jti replay accepted", err)
	}
	base := ProvisioningScope{Operation: ProvisioningCreate, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Template: "production", GroupID: f.group}
	if err = f.authorize(t, s.Credential, base, f.now, false); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*ProvisioningScope){"team": func(s *ProvisioningScope) { s.TeamID = "team-other" }, "project": func(s *ProvisioningScope) { s.ProjectKey = "other" }, "template": func(s *ProvisioningScope) { s.Template = "other" }, "group": func(s *ProvisioningScope) { s.GroupID = "pgrp_unknown" }, "operation": func(s *ProvisioningScope) { s.Operation = ProvisioningRetire }} {
		t.Run(name, func(t *testing.T) {
			scope := base
			edit(&scope)
			if err := f.authorize(t, s.Credential, scope, f.now, false); !errors.Is(err, ErrMachineDenied) {
				t.Fatal("wrong token scope accepted", err)
			}
		})
	}
	if err = f.authorize(t, s.Credential, base, s.ExpiresAt, false); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("expired token accepted", err)
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	if err = f.d.RotateMachineIdentityKey(t.Context(), f.r.TeamID, f.machine.ID, f.r.ActorID, "second", public, f.now); err != nil {
		t.Fatal(err)
	}
	if err = f.authorize(t, s.Credential, base, f.now, false); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("rotation left old token valid", err)
	}
	if _, err = f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, ProvisioningRead, f.provisioningProof(t, ProvisioningRead), machineTestAudience, f.now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("old key valid after rotation", err)
	}
}

func TestIntegrationMachineEnrollmentBudgetRollbackAndRevocation(t *testing.T) {
	f := newMachineFixture(t, "oidc")
	s, err := f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, ProvisioningEnroll, f.proof, machineTestAudience, f.now)
	if err != nil {
		t.Fatal(err)
	}
	scope := ProvisioningScope{Operation: ProvisioningEnroll, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, GroupID: f.group, EnrollmentMembers: 2, EnrollmentLifetime: time.Minute}
	if err = f.authorize(t, s.Credential, scope, f.now, false); err != nil {
		t.Fatal(err)
	}
	if err = f.authorize(t, s.Credential, scope, f.now, true); err != nil {
		t.Fatal("rolled-back operation spent enrollment budget", err)
	}
	if err = f.authorize(t, s.Credential, scope, f.now, false); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("aggregate enrollment budget exceeded", err)
	}
	scope.EnrollmentMembers = 1
	scope.EnrollmentLifetime = 11 * time.Minute
	if err = f.authorize(t, s.Credential, scope, f.now, false); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("enrollment lifetime exceeded", err)
	}
	if err = f.d.RevokeMachineIdentity(t.Context(), f.r.TeamID, f.machine.ID, f.r.ActorID, f.now); err != nil {
		t.Fatal(err)
	}
	scope.EnrollmentLifetime = time.Minute
	if err = f.authorize(t, s.Credential, scope, f.now, false); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("revoked machine token accepted", err)
	}
}

func TestIntegrationMachineWorkloadResolutionAndSnapshot(t *testing.T) {
	for _, kind := range []string{"oidc", "signing_key"} {
		t.Run(kind, func(t *testing.T) {
			f := newMachineFixture(t, kind)
			permission, err := f.d.CreateMachineWorkloadPermission(t.Context(), MachineWorkloadPermission{MachineID: f.machine.ID, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Workload: "test", Templates: []string{"production"}, ExpiresAt: f.now.Add(2 * time.Hour)}, f.r.ActorID, f.now)
			if err != nil {
				t.Fatal(err)
			}
			proof := f.proof
			aud := machineTestServer + "/v1/publisher-groups/" + f.group + "/resolve"
			if kind == "signing_key" {
				raw, e := publisherproof.Sign(f.machine.ID, "first", machineproof.Workload(f.group, "test", "resolve", "", "", nil), aud, f.key, f.now)
				if e != nil {
					t.Fatal(e)
				}
				proof = MachineProof{Assertion: raw}
			}
			machine := MachineWorkloadProof{MachineID: f.machine.ID, GroupID: f.group, Proof: proof, Audience: aud}
			resolved, err := f.d.ResolvePublisherGroupWorkload(t.Context(), f.group, "test", machineTestServer, oidc.WorkloadExecution{}, &machine, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.PublisherGroup != "production" || resolved.Connection.GroupName != "one" {
				t.Fatal("resolver confused template with concrete name", resolved)
			}
			data, _ := json.Marshal(resolved)
			if strings.Contains(string(data), "internal") || strings.Contains(string(data), "target") || strings.Contains(string(data), proof.Assertion) {
				t.Fatal("resolver leaked targets or secrets", string(data))
			}
			public, key, _ := ed25519.GenerateKey(rand.Reader)
			services := []string{f.group + "/api"}
			nonce := rand.Text()
			machine.Audience = machineTestServer + "/v1/machine-workload-sessions/exchange"
			if kind == "signing_key" {
				raw, e := publisherproof.Sign(f.machine.ID, "first", machineproof.Workload(f.group, "test", "exchange", base64.RawURLEncoding.EncodeToString(public), nonce, services), machine.Audience, f.key, f.now)
				if e != nil {
					t.Fatal(e)
				}
				machine.Proof = MachineProof{Assertion: raw}
			}
			digest := sha256.Sum256([]byte(machine.Proof.Assertion))
			r := ExchangeWorkloadRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, SourceFingerprint: f.r.SourceFingerprint, Workload: "test", Nonce: nonce, PublicKey: public, Services: services}
			r.Signature = ed25519.Sign(key, workloadproof.Exchange(r.TeamID, r.ProjectKey, r.Workload, r.SourceFingerprint, nonce, digest, services))
			session, err := f.d.ExchangeMachineWorkload(t.Context(), r, machine, f.now)
			if err != nil {
				t.Fatal(err)
			}
			replay, err := f.d.ExchangeMachineWorkload(t.Context(), r, machine, f.now)
			if err != nil || !reflect.DeepEqual(session, replay) {
				t.Fatal("exact exchange retry changed session", err)
			}
			r.Services = []string{f.group + "/db"}
			if _, err = f.d.ExchangeMachineWorkload(t.Context(), r, machine, f.now); err == nil {
				t.Fatal("session scope expanded")
			}
			if err = f.d.RevokeMachineWorkloadPermission(t.Context(), f.r.TeamID, permission.ID, f.r.ActorID, f.now); err != nil {
				t.Fatal(err)
			}
			if _, err = f.d.ListWorkloadServices(t.Context(), session.Credential, f.now); !errors.Is(err, ErrWorkloadDenied) {
				t.Fatal("revoked visitor permission accepted", err)
			}
			if _, err = f.d.ResolvePublisherGroupWorkload(t.Context(), f.group, "test", machineTestServer, oidc.WorkloadExecution{}, &machine, f.now); err == nil {
				t.Fatal("revoked permission resolved group")
			}
		})
	}
}

func startMachineWorkload(t *testing.T, f machineFixture) (WorkloadSession, ed25519.PrivateKey) {
	t.Helper()
	_, err := f.d.CreateMachineWorkloadPermission(t.Context(), MachineWorkloadPermission{MachineID: f.machine.ID, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Workload: "test", Templates: []string{"production"}, ExpiresAt: f.now.Add(2 * time.Hour)}, f.r.ActorID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	services := []string{f.group + "/api"}
	nonce := rand.Text()
	machine := MachineWorkloadProof{MachineID: f.machine.ID, GroupID: f.group, Proof: f.proof, Audience: machineTestServer + "/v1/machine-workload-sessions/exchange"}
	if f.machine.ProofKind == "signing_key" {
		raw, e := publisherproof.Sign(f.machine.ID, "first", machineproof.Workload(f.group, "test", "exchange", base64.RawURLEncoding.EncodeToString(public), nonce, services), machine.Audience, f.key, f.now)
		if e != nil {
			t.Fatal(e)
		}
		machine.Proof = MachineProof{Assertion: raw}
	}
	digest := sha256.Sum256([]byte(machine.Proof.Assertion))
	r := ExchangeWorkloadRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, SourceFingerprint: f.r.SourceFingerprint, Workload: "test", Nonce: nonce, PublicKey: public, Services: services}
	r.Signature = ed25519.Sign(key, workloadproof.Exchange(r.TeamID, r.ProjectKey, r.Workload, r.SourceFingerprint, nonce, digest, services))
	session, err := f.d.ExchangeMachineWorkload(t.Context(), r, machine, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return session, key
}

func (f machineFixture) attachmentProof(t *testing.T, s WorkloadSession, key ed25519.PrivateKey, at time.Time) (MachineProof, []byte, string) {
	t.Helper()
	audience := machineTestServer + "/v1/machine-workload-sessions/" + s.ID + "/assertions"
	proof := f.proof
	if f.machine.ProofKind == "signing_key" {
		raw, err := publisherproof.Sign(f.machine.ID, "first", machineproof.Workload(f.group, "test", "attach", base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), s.ID, nil), audience, f.key, at)
		if err != nil {
			t.Fatal(err)
		}
		proof = MachineProof{Assertion: raw}
	} else {
		trust := f.machine.Trust
		raw := f.issuer.Sign(t, map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": trust.Claims["sub"], "iat": f.now.Unix(), "exp": at.Add(time.Hour).Unix()})
		v, err := oidc.NewWorkloadVerifier(machineTestServer, f.issuer.Client)
		if err != nil {
			t.Fatal(err)
		}
		c, err := v.Verify(t.Context(), trust, raw)
		if err != nil {
			t.Fatal(err)
		}
		proof = MachineProof{Assertion: raw, Execution: c}
	}
	digest := sha256.Sum256([]byte(proof.Assertion))
	return proof, ed25519.Sign(key, workloadproof.Attach(s.ID, digest)), audience
}

func TestIntegrationMachineWorkloadFreshAssertionAndFixedScope(t *testing.T) {
	for _, kind := range []string{"oidc", "signing_key"} {
		t.Run(kind, func(t *testing.T) {
			f := newMachineFixture(t, kind)
			session, key := startMachineWorkload(t, f)
			original := session
			for i := 1; i <= 14; i++ {
				at := f.now.Add(time.Duration(i) * 30 * time.Second)
				proof, signature, audience := f.attachmentProof(t, session, key, at)
				attached, err := f.d.AttachMachineWorkloadAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, at)
				if err != nil {
					t.Fatal("fresh machine assertion", i, err)
				}
				if !reflect.DeepEqual(attached.ServiceIDs, original.ServiceIDs) || !attached.ExpiresAt.Equal(*original.ExpiresAt) || attached.Binding != original.Binding || attached.ID != original.ID {
					t.Fatal("attachment widened or replaced immutable session", attached)
				}
				if kind == "signing_key" {
					if _, err = f.d.AttachMachineWorkloadAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, at); !errors.Is(err, ErrMachineDenied) {
						t.Fatal("attached signed jti replay accepted", err)
					}
				} else {
					if _, err = f.d.AttachMachineWorkloadAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, at); err != nil {
						t.Fatal("valid OIDC attachment retry rejected", err)
					}
				}
				session, err = f.d.RenewWorkloadSession(t.Context(), attached.ID, attached.Credential, signWorkloadRenewal(attached, key), at)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !session.IdentityExpiresAt.After(original.IdentityExpiresAt) {
				t.Fatal("fresh proof did not advance identity expiry")
			}
			at := f.now.Add(7*time.Minute + 30*time.Second)
			proof, signature, audience := f.attachmentProof(t, session, key, at)
			if _, err := f.d.AttachMachineWorkloadAssertion(t.Context(), session.ID, session.Credential, proof, signature, "https://other.example/assertions", at); kind == "signing_key" && !errors.Is(err, ErrMachineDenied) {
				t.Fatal("wrong attachment audience accepted", err)
			}
			_, foreign, _ := ed25519.GenerateKey(rand.Reader)
			digest := sha256.Sum256([]byte(proof.Assertion))
			bad := ed25519.Sign(foreign, workloadproof.Attach(session.ID, digest))
			if _, err := f.d.AttachMachineWorkloadAssertion(t.Context(), session.ID, session.Credential, proof, bad, audience, at); !errors.Is(err, ErrWorkloadDenied) {
				t.Fatal("attachment without ephemeral key accepted", err)
			}
			if err := f.d.RevokeMachineIdentity(t.Context(), f.r.TeamID, f.machine.ID, f.r.ActorID, at); err != nil {
				t.Fatal(err)
			}
			if _, err := f.d.AttachMachineWorkloadAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, at); !errors.Is(err, ErrWorkloadDenied) {
				t.Fatal("revoked machine attached fresh proof", err)
			}
		})
	}
}

func TestIntegrationMachineReplayRetentionUsesFullProofExpiry(t *testing.T) {
	f := newMachineFixture(t, "signing_key")
	// shorten only the grant. replay state must still cover all sixty seconds
	// during which the signature would otherwise remain valid.
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.machine_provisioning_grants SET expires_at=$2 WHERE id=$1`, f.grant.ID, f.now.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	proof := f.provisioningProof(t, ProvisioningRead)
	if _, err := f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, ProvisioningRead, proof, machineTestAudience, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.CleanupWorkloads(t.Context(), f.now.Add(11*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	var proofs, sessions int
	if err := f.d.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM control.machine_proof_uses),(SELECT count(*) FROM control.machine_provisioning_sessions)`).Scan(&proofs, &sessions); err != nil {
		t.Fatal(err)
	}
	if proofs != 1 || sessions != 0 {
		t.Fatalf("cleanup truncated replay protection: proofs=%d sessions=%d", proofs, sessions)
	}
	if _, err := f.d.CleanupWorkloads(t.Context(), f.now.Add(time.Minute), 1); err != nil {
		t.Fatal(err)
	}
	if err := f.d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.machine_proof_uses`).Scan(&proofs); err != nil {
		t.Fatal(err)
	}
	if proofs != 0 {
		t.Fatal("expired replay state retained")
	}
	if _, err := f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, ProvisioningRead, proof, machineTestAudience, f.now.Add(time.Minute)); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("expired signed proof revived after cleanup", err)
	}
	if _, err := f.d.CleanupWorkloads(t.Context(), f.now, 0); err == nil {
		t.Fatal("unbounded cleanup accepted")
	}
}

func TestIntegrationMachineWorkloadCannotRestoreRemovedRightsOrDeadline(t *testing.T) {
	f := newMachineFixture(t, "signing_key")
	session, key := startMachineWorkload(t, f)
	originalDeadline := *session.ExpiresAt
	// a policy extension never moves this session's accepted hard deadline.
	current, err := f.d.GetProjectConfiguration(t.Context(), f.r.TeamID, f.r.ProjectKey, f.r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	f.r.ExpectedRevision = current.Revision
	p := f.r.Configuration.Workloads["test"]
	p.MaxDurationSeconds = 7200
	f.r.Configuration.Workloads["test"] = p
	if _, err = f.d.ApplyProjectConfiguration(t.Context(), f.r); err != nil {
		t.Fatal(err)
	}
	proof, signature, audience := f.attachmentProof(t, session, key, f.now.Add(30*time.Second))
	attached, err := f.d.AttachMachineWorkloadAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, f.now.Add(30*time.Second))
	if err != nil || !attached.ExpiresAt.Equal(originalDeadline) {
		t.Fatal("fresh proof widened hard deadline", attached, err)
	}
	// remove api and re-add it in applied policy. apply may only remove an
	// issued service right; neither a later apply nor fresh proof can restore it.
	current, err = f.d.GetProjectConfiguration(t.Context(), f.r.TeamID, f.r.ProjectKey, f.r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	f.r.ExpectedRevision = current.Revision
	p = f.r.Configuration.Workloads["test"]
	p.Services = []string{"db"}
	f.r.Configuration.Workloads["test"] = p
	current, err = f.d.ApplyProjectConfiguration(t.Context(), f.r)
	if err != nil {
		t.Fatal(err)
	}
	f.r.ExpectedRevision = current.Revision
	p.Services = []string{"api", "db"}
	f.r.Configuration.Workloads["test"] = p
	if _, err = f.d.ApplyProjectConfiguration(t.Context(), f.r); err != nil {
		t.Fatal(err)
	}
	proof, signature, audience = f.attachmentProof(t, session, key, f.now.Add(40*time.Second))
	attached, err = f.d.AttachMachineWorkloadAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, f.now.Add(40*time.Second))
	if err != nil || len(attached.ServiceIDs) != 0 {
		t.Fatal("fresh proof restored removed service right", attached, err)
	}
	if _, err = f.d.CheckWorkloadService(t.Context(), session.Credential, session.ServiceIDs[0], f.now.Add(40*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("removed right still usable", err)
	}
}

func TestIntegrationMachineCleanupBatchesAndRotationFence(t *testing.T) {
	f := newMachineFixture(t, "signing_key")
	session, key := startMachineWorkload(t, f)
	for range 3 {
		proof := f.provisioningProof(t, ProvisioningRead)
		if _, err := f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, ProvisioningRead, proof, machineTestAudience, f.now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.d.CleanupWorkloads(t.Context(), f.now.Add(2*time.Minute), 1); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.machine_provisioning_sessions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatal("cleanup ignored row budget", count)
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := f.d.RotateMachineIdentityKey(t.Context(), f.r.TeamID, f.machine.ID, f.r.ActorID, "second", public, f.now); err != nil {
		t.Fatal(err)
	}
	proof, signature, audience := f.attachmentProof(t, session, key, f.now.Add(30*time.Second))
	if _, err := f.d.AttachMachineWorkloadAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, f.now.Add(30*time.Second)); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("rotation left visitor attachment authority", err)
	}
	if _, err := f.d.CheckWorkloadService(t.Context(), session.Credential, session.ServiceIDs[0], f.now); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("rotation left visitor authority", err)
	}
}

func TestIntegrationMachineChangesPreserveLegacyTeamSelectorProof(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "machine_legacy_selector")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	request, key := workloadExchange(t, r, now)
	if err := d.pool.QueryRow(t.Context(), `SELECT display_name FROM control.teams WHERE id=$1`, r.TeamID).Scan(&request.TeamID); err != nil {
		t.Fatal(err)
	}
	signWorkloadRequest(&request, key)
	session, err := d.ExchangeWorkload(t.Context(), request, now)
	if err != nil || session.TeamID != r.TeamID {
		t.Fatal("canonicalization changed the signed request", session, err)
	}
}

func TestIntegrationMachineProvisioningRetainsAuthorityLocks(t *testing.T) {
	f := newMachineFixture(t, "oidc")
	s, err := f.d.ExchangeProvisioning(t.Context(), f.machine.ID, f.grant.ID, ProvisioningCreate, f.proof, machineTestAudience, f.now)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	scope := ProvisioningScope{Operation: ProvisioningCreate, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Template: "production"}
	if _, err = f.d.AuthorizeProvisioning(t.Context(), tx, s.Credential, scope, f.now); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	workers.Go(func() { done <- f.d.RevokeProvisioningGrant(ctx, f.r.TeamID, f.grant.ID, f.r.ActorID, f.now) })
	waitForPostgresBlock(t, ctx, f.d, int32(tx.Conn().PgConn().PID()), done)
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	if err = f.authorize(t, s.Credential, scope, f.now, false); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("revocation did not fence the next mutation", err)
	}
}
