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
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
)

const machineTestServer = "https://control.example"
const machineTestAudience = machineTestServer + "/v1/provisioning-sessions/exchange"

type machineFixture struct {
	d           *Database
	now         time.Time
	r           environmentPublisherTestProject
	machine     MachineIdentity
	grant       ProvisioningGrant
	key         ed25519.PrivateKey
	proof       MachineProof
	issuer      *githubtest.Issuer
	environment Environment
	collection  Collection
}

func newMachineFixture(t *testing.T, kind string) machineFixture {
	t.Helper()
	d, now := newControlStateIntegrationDatabase(t, "machine_"+kind)
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "db": {Protocol: "postgres"}})
	collection, _ := createTestCollection(t, d, r, "production", definition.Revision)
	environment, err := d.CreateEnvironment(t.Context(), CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, ActorID: r.ActorID, Name: "one", CollectionID: collection.ID, ExpectedCollectionRevision: collection.MutationRevision, Targets: EnvironmentTargets{"api": {Address: "api.internal:3000"}, "db": {Address: "db.internal:5432"}}, IdempotencyKey: "machine-one", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	retainedServiceEnvironment(t, d, r, "other", map[string]EnvironmentServicePublication{"otherapi": {Protocol: "http", Target: "other.internal:3000"}})
	trust := oidc.WorkloadTrust{Provider: "oidc", Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/keys", Audience: "tnl-machine", Claims: map[string]string{"sub": "machine:one"}}
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
	g, err := d.CreateProvisioningGrant(t.Context(), ProvisioningGrant{MachineID: m.ID, TeamID: r.TeamID, ProjectKey: r.ProjectKey, Scope: EnvironmentPermissionScope{CollectionID: collection.ID, IncludeFutureEnvironments: new(true)}, Services: []string{"api", "db"}, Operations: []ProvisioningOperation{ProvisioningCreate, ProvisioningRead, ProvisioningUpdate, ProvisioningEnroll, ProvisioningRevokeMember, ProvisioningRetire}, MaxEnrollmentMembers: 2, MaxEnrollmentSeconds: 600, EnrollmentBudget: 3, ExpiresAt: now.Add(time.Hour)}, r.ActorID, now)
	if err != nil {
		t.Fatal("grant", err)
	}
	f := machineFixture{d: d, now: now, r: r, machine: m, grant: g, key: key, environment: environment, collection: collection}
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
		if s.TokenType != "Bearer" || s.TeamID != f.r.TeamID || s.ProjectKey != f.r.ProjectKey || s.Scope.CollectionID != f.collection.ID || s.Scope.IncludeFutureEnvironments == nil || !*s.Scope.IncludeFutureEnvironments || !reflect.DeepEqual(s.Services, []string{"api", "db"}) {
			t.Fatal("missing authoritative provisioning scope", s)
		}
		scope := ProvisioningScope{Operation: op, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, EnvironmentID: f.environment.ID, Services: []string{"api", "db"}, EnrollmentMembers: 1, EnrollmentLifetime: time.Minute}
		if op == ProvisioningCreate {
			scope.EnvironmentID = ""
			scope.CollectionID = f.collection.ID
		}
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
	base := ProvisioningScope{Operation: ProvisioningCreate, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, CollectionID: f.collection.ID, Services: []string{"api", "db"}}
	if err = f.authorize(t, s.Credential, base, f.now, false); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*ProvisioningScope){"team": func(s *ProvisioningScope) { s.TeamID = "team-other" }, "project": func(s *ProvisioningScope) { s.ProjectKey = "other" }, "collection": func(s *ProvisioningScope) { s.CollectionID = "col_unknown" }, "service": func(s *ProvisioningScope) { s.Services = []string{"otherapi"} }, "operation": func(s *ProvisioningScope) { s.Operation = ProvisioningRetire }} {
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
	scope := ProvisioningScope{Operation: ProvisioningEnroll, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, EnvironmentID: f.environment.ID, Services: []string{"api", "db"}, EnrollmentMembers: 2, EnrollmentLifetime: time.Minute}
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
			permission, err := f.d.CreateEnvironmentVisitorPermission(t.Context(), EnvironmentVisitorPermission{MachineID: f.machine.ID, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Scope: EnvironmentPermissionScope{EnvironmentIDs: []string{f.environment.ID}}, Services: []string{"api", "db"}, MaxDurationSeconds: 3600, ExpiresAt: f.now.Add(2 * time.Hour)}, f.r.ActorID, f.now)
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := f.d.EnvironmentVisitorIdentityPolicy(t.Context(), permission.ID, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.ID != f.machine.ID || resolved.TeamID != f.r.TeamID {
				t.Fatal("permission selected another machine identity", resolved)
			}
			data, _ := json.Marshal(resolved)
			if strings.Contains(string(data), "internal") || strings.Contains(string(data), "target") || f.proof.Assertion != "" && strings.Contains(string(data), f.proof.Assertion) {
				t.Fatal("resolver leaked targets or secrets", string(data))
			}
			r, _ := machineVisitorPreparation(t, f, permission.ID, map[string]string{"api": "http"}, f.now)
			prepared, err := f.d.PrepareEnvironmentVisitor(t.Context(), r, f.now)
			if err != nil {
				t.Fatal(err)
			}
			replay, err := f.d.PrepareEnvironmentVisitor(t.Context(), r, f.now)
			if err != nil || !reflect.DeepEqual(prepared, replay) {
				t.Fatal("exact exchange retry changed session", err)
			}
			r.Services = map[string]string{"db": "postgres"}
			if _, err = f.d.PrepareEnvironmentVisitor(t.Context(), r, f.now); err == nil {
				t.Fatal("session scope expanded")
			}
			if err = f.d.RevokeEnvironmentVisitorPermission(t.Context(), f.r.TeamID, permission.ID, f.r.ActorID, f.now); err != nil {
				t.Fatal(err)
			}
			if _, err = f.d.ListWorkloadServices(t.Context(), prepared.Session.Credential, f.now); !errors.Is(err, ErrWorkloadDenied) {
				t.Fatal("revoked visitor permission accepted", err)
			}
			if _, err = f.d.EnvironmentVisitorIdentityPolicy(t.Context(), permission.ID, f.now); err == nil {
				t.Fatal("revoked permission resolved group")
			}
		})
	}
}

func machineVisitorPreparation(t *testing.T, f machineFixture, permission string, services map[string]string, now time.Time) (PrepareEnvironmentVisitorRequest, ed25519.PrivateKey) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := PrepareEnvironmentVisitorRequest{ProjectKey: f.r.ProjectKey, EnvironmentID: f.environment.ID, PermissionID: permission, Audience: machineTestServer + "/v1/environment-visitor-sessions/prepare", Nonce: rand.Text(), PublicKey: public, Services: services, Proof: f.proof}
	signMachineVisitorPreparation(t, f, &r, key, now)
	return r, key
}

func signMachineVisitorPreparation(t *testing.T, f machineFixture, r *PrepareEnvironmentVisitorRequest, key ed25519.PrivateKey, now time.Time) {
	t.Helper()
	encoded := base64.RawURLEncoding.EncodeToString(r.PublicKey)
	if f.machine.ProofKind == "signing_key" {
		raw, err := publisherproof.Sign(f.machine.ID, "first", machineproof.EnvironmentVisitor(r.PermissionID, r.EnvironmentID, "prepare", encoded, r.Nonce, r.Services), r.Audience, f.key, now)
		if err != nil {
			t.Fatal(err)
		}
		r.Proof = MachineProof{Assertion: raw}
	}
	digest := sha256.Sum256([]byte(r.Proof.Assertion))
	r.Signature = ed25519.Sign(key, machineproof.EnvironmentVisitorPossession(r.ProjectKey, r.PermissionID, r.EnvironmentID, "prepare", encoded, r.Nonce, r.Services, digest))
}

func startMachineWorkload(t *testing.T, f machineFixture) (WorkloadSession, ed25519.PrivateKey) {
	t.Helper()
	permission, err := f.d.CreateEnvironmentVisitorPermission(t.Context(), EnvironmentVisitorPermission{MachineID: f.machine.ID, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Scope: EnvironmentPermissionScope{EnvironmentIDs: []string{f.environment.ID}}, Services: []string{"api", "db"}, MaxDurationSeconds: 3600, ExpiresAt: f.now.Add(2 * time.Hour)}, f.r.ActorID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	r, key := machineVisitorPreparation(t, f, permission.ID, map[string]string{"api": "http"}, f.now)
	prepared, err := f.d.PrepareEnvironmentVisitor(t.Context(), r, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return prepared.Session, key
}

func (f machineFixture) attachmentProof(t *testing.T, s WorkloadSession, key ed25519.PrivateKey, at time.Time) (MachineProof, []byte, string, []byte) {
	t.Helper()
	audience := machineTestServer + "/v1/environment-visitor-sessions/" + s.ID + "/assertions"
	var permission, environment string
	var encoded, originalPublic []byte
	if err := f.d.pool.QueryRow(t.Context(), `SELECT binding.permission_id,binding.environment_id,binding.expected_protocols,session.public_key FROM control.workload_session_machines binding JOIN control.workload_sessions session ON session.id=binding.session_id WHERE binding.session_id=$1`, s.ID).Scan(&permission, &environment, &encoded, &originalPublic); err != nil {
		t.Fatal(err)
	}
	var services map[string]string
	if err := json.Unmarshal(encoded, &services); err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(originalPublic)
	proof := f.proof
	if f.machine.ProofKind == "signing_key" {
		raw, err := publisherproof.Sign(f.machine.ID, "first", machineproof.EnvironmentVisitor(permission, environment, "attach", public, s.ID, services), audience, f.key, at)
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
	message := machineproof.EnvironmentVisitorPossession(f.r.ProjectKey, permission, environment, "attach", public, s.ID, services, digest)
	return proof, ed25519.Sign(key, message), audience, message
}

func TestIntegrationMachineWorkloadFreshAssertionAndFixedScope(t *testing.T) {
	for _, kind := range []string{"oidc", "signing_key"} {
		t.Run(kind, func(t *testing.T) {
			f := newMachineFixture(t, kind)
			session, key := startMachineWorkload(t, f)
			original := session
			for i := 1; i <= 14; i++ {
				at := f.now.Add(time.Duration(i) * 30 * time.Second)
				proof, signature, audience, _ := f.attachmentProof(t, session, key, at)
				attached, err := f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, at)
				if err != nil {
					t.Fatal("fresh machine assertion", i, err)
				}
				if !reflect.DeepEqual(attached.ServiceIDs, original.ServiceIDs) || !attached.ExpiresAt.Equal(*original.ExpiresAt) || attached.Binding != original.Binding || attached.ID != original.ID {
					t.Fatal("attachment widened or replaced immutable session", attached)
				}
				if kind == "signing_key" {
					if _, err = f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, at); !errors.Is(err, ErrMachineDenied) {
						t.Fatal("attached signed jti replay accepted", err)
					}
				} else {
					if _, err = f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, at); err != nil {
						t.Fatal("valid OIDC attachment retry rejected", err)
					}
				}
				session, err = f.d.RenewEnvironmentVisitorSession(t.Context(), attached.ID, attached.Credential, signWorkloadRenewal(attached, key), at)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !session.IdentityExpiresAt.After(original.IdentityExpiresAt) {
				t.Fatal("fresh proof did not advance identity expiry")
			}
			at := f.now.Add(7*time.Minute + 30*time.Second)
			proof, signature, audience, message := f.attachmentProof(t, session, key, at)
			if _, err := f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, "https://other.example/assertions", at); kind == "signing_key" && !errors.Is(err, ErrMachineDenied) {
				t.Fatal("wrong attachment audience accepted", err)
			}
			foreignPublic, foreign, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bad := ed25519.Sign(foreign, message)
			if !ed25519.Verify(foreignPublic, message, bad) || ed25519.Verify(key.Public().(ed25519.PublicKey), message, bad) || !ed25519.Verify(key.Public().(ed25519.PublicKey), message, signature) {
				t.Fatal("foreign-key fixture did not sign the unchanged attachment message")
			}
			if _, err := f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, bad, audience, at); !errors.Is(err, ErrMachineDenied) {
				t.Fatal("attachment without ephemeral key accepted", err)
			}
			if attached, err := f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, at); err != nil || attached.ID != session.ID || attached.Binding != original.Binding || !attached.ExpiresAt.Equal(*original.ExpiresAt) {
				t.Fatal("valid attachment failed after key-only rejection", err)
			}
			if _, err := f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, at); kind == "signing_key" && !errors.Is(err, ErrMachineDenied) || kind == "oidc" && err != nil {
				t.Fatal("key-only probe changed registered proof replay behavior", err)
			}
			if err := f.d.RevokeMachineIdentity(t.Context(), f.r.TeamID, f.machine.ID, f.r.ActorID, at); err != nil {
				t.Fatal(err)
			}
			if _, err := f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, at); !errors.Is(err, ErrWorkloadDenied) {
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
	permission, err := f.d.CreateEnvironmentVisitorPermission(t.Context(), EnvironmentVisitorPermission{MachineID: f.machine.ID, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Scope: EnvironmentPermissionScope{EnvironmentIDs: []string{f.environment.ID}}, Services: []string{"api", "db"}, MaxDurationSeconds: 3600, ExpiresAt: f.now.Add(3 * time.Hour)}, f.r.ActorID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	request, key := machineVisitorPreparation(t, f, permission.ID, map[string]string{"api": "http"}, f.now)
	prepared, err := f.d.PrepareEnvironmentVisitor(t.Context(), request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session
	originalDeadline := *session.ExpiresAt
	if !originalDeadline.Equal(f.now.Add(time.Hour)) {
		t.Fatal("original permission did not set its own fixed window")
	}
	// a separate approved permission can admit its own longer session, never
	// edit the original permission or rebind an already admitted nonce.
	largerPermission, err := f.d.CreateEnvironmentVisitorPermission(t.Context(), EnvironmentVisitorPermission{MachineID: f.machine.ID, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Scope: EnvironmentPermissionScope{EnvironmentIDs: []string{f.environment.ID}}, Services: []string{"api", "db"}, MaxDurationSeconds: 7200, ExpiresAt: f.now.Add(3 * time.Hour)}, f.r.ActorID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	at := f.now.Add(30 * time.Second)
	largerRequest, _ := machineVisitorPreparation(t, f, largerPermission.ID, request.Services, at)
	larger, err := f.d.PrepareEnvironmentVisitor(t.Context(), largerRequest, at)
	if err != nil || largerPermission.ID == permission.ID || larger.Session.ID == session.ID || !larger.Session.ExpiresAt.Equal(at.Add(2*time.Hour)) {
		t.Fatal("separate duration permission did not admit its own fixed window", err)
	}
	retry := request
	signMachineVisitorPreparation(t, f, &retry, key, at)
	if recovered, err := f.d.PrepareEnvironmentVisitor(t.Context(), retry, at); err != nil || !reflect.DeepEqual(recovered.Session, session) {
		t.Fatal("same-permission retry changed the original fixed session", err)
	}
	rebound := request
	rebound.PermissionID = largerPermission.ID
	signMachineVisitorPreparation(t, f, &rebound, key, at)
	if _, err := f.d.PrepareEnvironmentVisitor(t.Context(), rebound, at); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("original nonce rebound to the longer permission", err)
	}
	audience := machineTestServer + "/v1/environment-visitor-sessions/" + session.ID + "/assertions"
	public := base64.RawURLEncoding.EncodeToString(request.PublicKey)
	raw, err := publisherproof.Sign(f.machine.ID, "first", machineproof.EnvironmentVisitor(largerPermission.ID, request.EnvironmentID, "attach", public, session.ID, request.Services), audience, f.key, at)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(raw))
	reboundSignature := ed25519.Sign(key, machineproof.EnvironmentVisitorPossession(request.ProjectKey, largerPermission.ID, request.EnvironmentID, "attach", public, session.ID, request.Services, digest))
	if _, err := f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, MachineProof{Assertion: raw}, reboundSignature, audience, at); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("attachment rebound the original session to the longer permission", err)
	}
	proof, signature, audience, _ := f.attachmentProof(t, session, key, f.now.Add(30*time.Second))
	attached, err := f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, f.now.Add(30*time.Second))
	if err != nil || attached.Binding != session.Binding || !attached.ExpiresAt.Equal(originalDeadline) {
		t.Fatal("fresh proof widened hard deadline", attached, err)
	}
	session, err = f.d.RenewEnvironmentVisitorSession(t.Context(), session.ID, session.Credential, signWorkloadRenewal(attached, key), at)
	if err != nil || session.Binding != attached.Binding || !session.ExpiresAt.Equal(originalDeadline) {
		t.Fatal("renewal adopted the longer permission's deadline", err)
	}
	var boundPermission string
	var originalDuration int
	if err := f.d.pool.QueryRow(t.Context(), `SELECT binding.permission_id,permission.max_duration_seconds FROM control.workload_session_machines binding JOIN control.machine_workload_permissions permission ON permission.id=binding.permission_id WHERE binding.session_id=$1`, session.ID).Scan(&boundPermission, &originalDuration); err != nil || boundPermission != permission.ID || originalDuration != 3600 {
		t.Fatal("attachment or renewal changed the original permission", err)
	}
	// removal retires the accepted immutable service ID. re-adding its logical
	// name creates a new ID and must never restore this session's accepted right.
	definition := environmentDefinition(t, f.d, f.r, map[string]ServiceDefinitionService{"db": {Protocol: "postgres"}})
	current, err := f.d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, ActorID: f.r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: f.environment.ID, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: definition.Revision}, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	definition = environmentDefinition(t, f.d, f.r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "db": {Protocol: "postgres"}})
	if _, err = f.d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, ActorID: f.r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: current.ID, ExpectedRevision: current.MutationRevision, DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "api.internal:3000"}, "db": {Address: "db.internal:5432"}}}, Now: f.now}); err != nil {
		t.Fatal(err)
	}
	proof, signature, audience, _ = f.attachmentProof(t, session, key, f.now.Add(40*time.Second))
	attached, err = f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, f.now.Add(40*time.Second))
	if err != nil || len(attached.ServiceIDs) != 0 {
		t.Fatal("fresh proof restored removed service right", attached, err)
	}
	if services, err := f.d.ListWorkloadServices(t.Context(), session.Credential, f.now.Add(40*time.Second)); err != nil || len(services) != 0 {
		t.Fatal("fresh proof restored removed live service", err)
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
	proof, signature, audience, _ := f.attachmentProof(t, session, key, f.now.Add(30*time.Second))
	if _, err := f.d.AttachEnvironmentVisitorAssertion(t.Context(), session.ID, session.Credential, proof, signature, audience, f.now.Add(30*time.Second)); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("rotation left visitor attachment authority", err)
	}
	if _, err := f.d.CheckWorkloadService(t.Context(), session.Credential, session.ServiceIDs[0], f.now); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("rotation left visitor authority", err)
	}
}

func TestIntegrationMachineChangesPreserveLegacyTeamSelectorProof(t *testing.T) {
	f := newMachineFixture(t, "signing_key")
	permission, err := f.d.CreateEnvironmentVisitorPermission(t.Context(), EnvironmentVisitorPermission{MachineID: f.machine.ID, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, Scope: EnvironmentPermissionScope{EnvironmentIDs: []string{f.environment.ID}}, Services: []string{"api"}, MaxDurationSeconds: 3600, ExpiresAt: f.now.Add(time.Hour)}, f.r.ActorID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := machineVisitorPreparation(t, f, permission.ID, map[string]string{"api": "http"}, f.now)
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.teams SET display_name='renamed-team' WHERE id=$1`, f.r.TeamID); err != nil {
		t.Fatal(err)
	}
	prepared, err := f.d.PrepareEnvironmentVisitor(t.Context(), request, f.now)
	if err != nil || prepared.Session.TeamID != f.r.TeamID {
		t.Fatal("human team selector changed immutable signed permission scope", err)
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
	scope := ProvisioningScope{Operation: ProvisioningCreate, TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, CollectionID: f.collection.ID, Services: []string{"api", "db"}}
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
