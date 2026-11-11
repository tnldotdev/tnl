package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
)

func publicationMachine(t *testing.T, d *Database, team, actor, kind string, now time.Time) machineFixture {
	t.Helper()
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := oidc.WorkloadTrust{Provider: "oidc", Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/keys", Audience: "tnl-machine", Claims: map[string]string{"sub": "machine:publisher"}}
	r := RegisterMachineRequest{TeamID: team, ActorID: actor, Name: "application", ProofKind: kind}
	if kind == "oidc" {
		r.Trust = trust
	} else {
		r.KeyID = "first"
		r.PublicKey = public
	}
	m, err := d.RegisterMachineIdentity(t.Context(), r, now)
	if err != nil {
		t.Fatal(err)
	}
	f := machineFixture{d: d, now: now, r: ApplyProjectConfigurationRequest{TeamID: team, ActorID: actor}, machine: m, key: key}
	if kind == "oidc" {
		f.issuer = githubtest.NewKeySet(t, trust.JWKSURL)
	}
	return f
}

func (f machineFixture) publicationProof(t *testing.T, resource, namespace, operation, public, nonce, audience string, at time.Time) MachineProof {
	t.Helper()
	if f.machine.ProofKind == "signing_key" {
		raw, err := publisherproof.Sign(f.machine.ID, "first", machineproof.Publication(resource, namespace, operation, public, nonce), audience, f.key, at)
		if err != nil {
			t.Fatal(err)
		}
		return MachineProof{Assertion: raw}
	}
	trust := f.machine.Trust
	raw := f.issuer.Sign(t, map[string]any{"iss": trust.Issuer, "aud": trust.Audience, "sub": trust.Claims["sub"], "iat": f.now.Unix(), "exp": at.Add(2 * time.Minute).Unix()})
	v, err := oidc.NewWorkloadVerifier(machineTestServer, f.issuer.Client)
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(t.Context(), trust, raw)
	if err != nil {
		t.Fatal(err)
	}
	return MachineProof{Assertion: raw, Execution: c}
}

func publicationExchange(t *testing.T, f machineFixture, resource, namespace string) (MachinePublicationExchange, ed25519.PrivateKey) {
	t.Helper()
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	encoded := base64.RawURLEncoding.EncodeToString(public)
	nonce := rand.Text()
	proof := f.publicationProof(t, resource, namespace, "exchange", encoded, nonce, machineTestServer+"/v1/machine-publication-sessions/exchange", f.now)
	digest := sha256.Sum256([]byte(proof.Assertion))
	return MachinePublicationExchange{MachineID: f.machine.ID, Resource: resource, Namespace: namespace, Nonce: nonce, PublicKey: public, Proof: proof, Signature: ed25519.Sign(key, machineproof.PublicationPossession(resource, namespace, "exchange", encoded, nonce, digest))}, key
}

func TestIntegrationMachinePublicationExistingRunAndRenewal(t *testing.T) {
	for _, kind := range []string{"oidc", "signing_key"} {
		t.Run(kind, func(t *testing.T) {
			d, now, base, _ := newPublishRunPrerequisites(t)
			f := publicationMachine(t, d, base.TeamID, base.ActingIdentityID, kind, now)
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
			if p.CreatorID != "" || p.CreatorMachineID != f.machine.ID || p.Scope.PublicURLID != base.PublicURLID {
				t.Fatal("machine borrowed human authority", p)
			}
			if _, err = d.AuthenticateAccessToken(t.Context(), credentials.AccessToken(session.AccessToken), now); err == nil {
				t.Fatal("publisher became human")
			}
			if _, err = d.ListWorkloadServices(t.Context(), session.AccessToken, now); err == nil {
				t.Fatal("publisher became visitor")
			}
			u, err := d.GetPublicURLForAuthorization(t.Context(), base.PublicURLID)
			if err != nil {
				t.Fatal(err)
			}
			r := reviewRunRequest(t, d, p, key, u, "machine-run")
			r.ActingMachineID = p.CreatorMachineID
			run, err := d.CreatePublishRun(t.Context(), r, now, 10*time.Minute, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if run.ExpiresAt.After(session.IdentityExpiresAt) {
				t.Fatal("run exceeded source proof")
			}
			auth := PublishRunAuthentication{PublishRunID: run.PublishRunID, PublicURLID: u.ID, PublishRunNumber: run.PublishRunNumber, PublishRunToken: run.PublishRunToken}
			original := session.Publisher
			for i := 1; i <= 14; i++ {
				at := now.Add(time.Duration(i) * 30 * time.Second)
				encoded := base64.RawURLEncoding.EncodeToString(exchange.PublicKey)
				proof := f.publicationProof(t, u.ID, "", "refresh", encoded, session.Id, machineTestServer+"/v1/machine-publication-sessions/"+session.Id+"/refresh", at)
				digest := sha256.Sum256([]byte(proof.Assertion))
				signature := ed25519.Sign(key, machineproof.PublicationPossession(u.ID, "", "refresh", encoded, session.Id, digest))
				refreshed, e := d.RefreshMachinePublication(t.Context(), session.Id, proof, signature, machineTestServer+"/v1/machine-publication-sessions/"+session.Id+"/refresh", at)
				if e != nil {
					t.Fatal("refresh", i, e)
				}
				if !reflect.DeepEqual(original, refreshed.Publisher) {
					t.Fatal("refresh expanded publisher scope")
				}
				session = refreshed
				run, e = d.HeartbeatPublishRun(t.Context(), auth, at, 10*time.Minute, time.Minute)
				if e != nil {
					t.Fatal("heartbeat", i, e)
				}
				if run.ExpiresAt.After(session.IdentityExpiresAt) {
					t.Fatal("heartbeat exceeded current proof")
				}
			}
			var actor *string
			var machine string
			if err = d.pool.QueryRow(t.Context(), `SELECT acting_identity_id,acting_machine_id FROM control.publish_runs WHERE id=$1`, run.PublishRunID).Scan(&actor, &machine); err != nil || actor != nil || machine != f.machine.ID {
				t.Fatal("incorrect run provenance", actor, machine, err)
			}
			if err = d.RevokeMachinePublicationPermission(t.Context(), base.TeamID, permission.ID, base.ActingIdentityID, now.Add(7*time.Minute)); err != nil {
				t.Fatal(err)
			}
			var closed bool
			if err = d.pool.QueryRow(t.Context(), `SELECT closed_at IS NOT NULL FROM control.publish_runs WHERE id=$1`, run.PublishRunID).Scan(&closed); err != nil || !closed {
				t.Fatal("revocation left run open before another heartbeat", closed, err)
			}
			if _, err = d.AuthenticatePublisherAccess(t.Context(), session.AccessToken, "", now.Add(7*time.Minute)); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("revoked publication token accepted", err)
			}
			if _, err = d.HeartbeatPublishRun(t.Context(), auth, now.Add(7*time.Minute+time.Second), time.Minute, time.Minute); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("revoked run renewed", err)
			}
		})
	}
}

func TestIntegrationMachinePublicationRevocationClosesRouting(t *testing.T) {
	for _, operation := range []string{"permission", "identity", "rotation"} {
		for _, scope := range []string{"resource", "namespace"} {
			t.Run(operation+"/"+scope, func(t *testing.T) {
				d, now, base, leases := newPublishRunPrerequisites(t)
				f := publicationMachine(t, d, base.TeamID, base.ActingIdentityID, "signing_key", now)
				approve := func(resource, namespace string) MachinePublicationPermission {
					t.Helper()
					r := MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Resource: resource, Namespace: namespace, ExpiresAt: now.Add(time.Hour)}
					if namespace != "" {
						r.DomainID = "domain_session"
					}
					p, err := d.CreateMachinePublicationPermission(t.Context(), r, base.ActingIdentityID, now)
					if err != nil {
						t.Fatal(err)
					}
					return p
				}
				start := func(permission MachinePublicationPermission) publishRunFixture {
					t.Helper()
					exchange, key := publicationExchange(t, f, permission.Resource, permission.Namespace)
					session, err := d.ExchangeMachinePublication(t.Context(), exchange, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
					if err != nil {
						t.Fatal(err)
					}
					p, err := d.AuthenticatePublisherAccess(t.Context(), session.AccessToken, "", now)
					if err != nil {
						t.Fatal(err)
					}
					var u PublicURL
					if permission.Namespace != "" {
						invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
						if err != nil {
							t.Fatal(err)
						}
						u, err = d.AllocatePublisherPublicURL(t.Context(), p, invocation, "http://127.0.0.1:3000", nil, nil, now, PublisherPublicURLOptions{AccessMode: VisitorAccessRestricted})
						if err != nil {
							t.Fatal(err)
						}
						// dns delivery is outside this revocation boundary.
						if _, err = d.pool.Exec(t.Context(), `UPDATE control.public_urls SET dns_state='published',dns_available_at=NULL WHERE id=$1`, u.ID); err != nil {
							t.Fatal(err)
						}
					} else {
						u, err = d.GetPublicURLForAuthorization(t.Context(), permission.Resource)
						if err != nil {
							t.Fatal(err)
						}
					}
					r := reviewRunRequest(t, d, p, key, u, rand.Text())
					r.ActingMachineID = p.CreatorMachineID
					run, err := d.CreatePublishRun(t.Context(), r, now, time.Minute, time.Minute)
					if err != nil {
						t.Fatal(err)
					}
					fixture := publishRunFixture{database: d, now: now, request: r, setup: run, leases: leases}
					readyTestSession(t, fixture)
					return fixture
				}
				resource, namespace := base.PublicURLID, ""
				if scope == "namespace" {
					resource, namespace = "", "application.session.example.test"
				}
				permission := approve(resource, namespace)
				affected := []publishRunFixture{start(permission)}
				if scope == "namespace" {
					// one permission may have several independent native sessions.
					affected = append(affected, start(permission))
				}
				other := start(approve("", "other.session.example.test"))
				ingress := registerTestIngress(t, d, now)
				before, err := d.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now)
				if err != nil || len(before.Entries) != len(affected)+1 {
					t.Fatal("publications not routable before revocation", before, err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				gate, err := d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				if _, err = controlstatedb.New(gate).LockPublishRun(ctx, affected[0].setup.PublishRunID); err != nil {
					t.Fatal(err)
				}
				heartbeat := make(chan error, 1)
				workers.Go(func() {
					_, err := d.HeartbeatPublishRun(ctx, affected[0].authentication(), now.Add(time.Second), time.Minute, time.Minute)
					heartbeat <- err
				})
				pid := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), heartbeat)
				revoked := make(chan error, 1)
				workers.Go(func() {
					at := now.Add(2 * time.Second)
					var err error
					switch operation {
					case "permission":
						err = d.RevokeMachinePublicationPermission(ctx, base.TeamID, permission.ID, base.ActingIdentityID, at)
					case "identity":
						err = d.RevokeMachineIdentity(ctx, base.TeamID, f.machine.ID, base.ActingIdentityID, at)
					case "rotation":
						public, _, e := ed25519.GenerateKey(rand.Reader)
						if e != nil {
							err = e
						} else {
							err = d.RotateMachineIdentityKey(ctx, base.TeamID, f.machine.ID, base.ActingIdentityID, "second", public, at)
						}
					}
					revoked <- err
				})
				waitForPostgresBlock(t, ctx, d, pid, revoked)
				if err = gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err = awaitIntegrationResult(t, ctx, heartbeat); err != nil {
					t.Fatal("earlier heartbeat deadlocked with revocation", err)
				}
				if err = awaitIntegrationResult(t, ctx, revoked); err != nil {
					t.Fatalf("revocation did not join heartbeat: %v (%#v)", err, err)
				}
				wantEntries := 1
				if operation != "permission" {
					affected = append(affected, other)
					wantEntries = 0
				}
				for _, fixture := range affected {
					var closed bool
					if err = d.pool.QueryRow(ctx, `SELECT state='closed' AND close_reason='publisher_revoked' AND closed_at=$2
						AND NOT EXISTS(SELECT 1 FROM control.publish_run_connection_slots WHERE publish_run_id=$1 AND closed_at IS NULL)
						FROM control.publish_runs WHERE id=$1`, fixture.setup.PublishRunID, now.Add(2*time.Second)).Scan(&closed); err != nil || !closed {
						t.Fatal("run or publisher connections stayed open before heartbeat", closed, err)
					}
				}
				after, err := d.ReadIngressRoutingTableSnapshot(ctx, ingress.IngressLeaseIdentity, now.Add(3*time.Second))
				if err != nil || len(after.Entries) != wantEntries || after.RoutingTableRevision <= before.RoutingTableRevision {
					t.Fatal("revocation did not remove exactly its current routing entries", after, err)
				}
				if operation == "permission" {
					if _, err = d.HeartbeatPublishRun(ctx, other.authentication(), now.Add(3*time.Second), time.Minute, time.Minute); err != nil {
						t.Fatal("another permission was revoked", err)
					}
				}
			})
		}
	}
}

func TestIntegrationMachinePublicationAllocationIsolatedAndPolicy(t *testing.T) {
	d, now, base, _ := newPublishRunPrerequisites(t)
	f := publicationMachine(t, d, base.TeamID, base.ActingIdentityID, "signing_key", now)
	namespace := "temporary.session.example.test"
	_, err := d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Namespace: namespace, DomainID: "domain_session", ExpiresAt: now.Add(time.Hour)}, base.ActingIdentityID, now)
	if err != nil {
		t.Fatal(err)
	}
	exchange, key := publicationExchange(t, f, "", namespace)
	session, err := d.ExchangeMachinePublication(t.Context(), exchange, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := d.AuthenticatePublisherAccess(t.Context(), session.AccessToken, "", now)
	if err != nil {
		t.Fatal(err)
	}
	invocation, _ := opaqueid.New(opaqueid.InvocationPrefix)
	u, err := d.AllocatePublisherPublicURL(t.Context(), p, invocation, "http://127.0.0.1:3000", nil, nil, now, PublisherPublicURLOptions{AccessMode: VisitorAccessRestricted})
	if err != nil {
		t.Fatal(err)
	}
	if u.AccessMode != VisitorAccessRestricted || !u.Ephemeral {
		t.Fatal("allocation defaults changed", u)
	}
	var actor *string
	var machine string
	if err = d.pool.QueryRow(t.Context(), `SELECT created_by_identity_id,created_by_machine_id FROM control.public_urls WHERE id=$1`, u.ID).Scan(&actor, &machine); err != nil || actor != nil || machine != f.machine.ID {
		t.Fatal("allocation impersonated human", actor, machine, err)
	}
	invocation2, _ := opaqueid.New(opaqueid.InvocationPrefix)
	if _, err = d.AllocatePublisherPublicURL(t.Context(), p, invocation2, "http://127.0.0.1:3000", nil, nil, now, PublisherPublicURLOptions{AccessMode: VisitorAccessAnonymous}); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("anonymous exceeded approval", err)
	}
	exchange2, _ := publicationExchange(t, f, "", namespace)
	second, err := d.ExchangeMachinePublication(t.Context(), exchange2, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := d.AuthenticatePublisherAccess(t.Context(), second.AccessToken, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := d.PublisherMayStartRun(t.Context(), other, u.ID); err != nil || allowed {
		t.Fatal("namespace grant acquired sibling allocation", err)
	}
	r := reviewRunRequest(t, d, p, key, u, "allocation-run")
	r.ActingMachineID = p.CreatorMachineID
	if _, err = d.CreatePublishRun(t.Context(), r, now, time.Minute, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err = d.DeleteAuthorizedPublicURL(t.Context(), AuthorizedPublicURLDeleteRequest{PublicURLID: base.PublicURLID, TeamID: base.TeamID, ActingMachineID: f.machine.ID, PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID}, now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("allocator deleted saved resource", err)
	}
	approvedNS := "anonymous.session.example.test"
	if _, err = d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Namespace: approvedNS, DomainID: "domain_session", AllowAnonymous: true, ExpiresAt: now.Add(time.Hour)}, base.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	approvedExchange, _ := publicationExchange(t, f, "", approvedNS)
	approvedSession, err := d.ExchangeMachinePublication(t.Context(), approvedExchange, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
	if err != nil {
		t.Fatal(err)
	}
	approvedPublisher, err := d.AuthenticatePublisherAccess(t.Context(), approvedSession.AccessToken, "", now)
	if err != nil {
		t.Fatal(err)
	}
	invocation3, _ := opaqueid.New(opaqueid.InvocationPrefix)
	anonymous, err := d.AllocatePublisherPublicURL(t.Context(), approvedPublisher, invocation3, "http://127.0.0.1:3000", nil, nil, now, PublisherPublicURLOptions{AccessMode: VisitorAccessAnonymous})
	if err != nil || anonymous.AccessMode != VisitorAccessAnonymous {
		t.Fatal("explicit anonymous approval ineffective", anonymous, err)
	}
}

func TestIntegrationMachinePublicationRemoteBoundaryAndLocalMetadata(t *testing.T) {
	d, now, base, _ := newPublishRunPrerequisites(t)
	f := publicationMachine(t, d, base.TeamID, base.ActingIdentityID, "signing_key", now)
	r := ApplyProjectConfigurationRequest{TeamID: base.TeamID, ActorID: base.ActingIdentityID, ProjectKey: "equipment", SourceFingerprint: shaFingerprint(), Now: now, Configuration: ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"remote": {DomainID: "domain_session"}}, Services: map[string]ProjectServiceConfiguration{"remoteapp": {PublisherGroup: "remote", Target: "http://127.0.0.1:3000"}}}}
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied.Groups) != 1 {
		t.Fatal("missing remote group")
	}
	ns := applied.Groups[0].Namespace
	if _, err = d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Namespace: ns, DomainID: "domain_session", ExpiresAt: now.Add(time.Hour)}, base.ActingIdentityID, now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("remote namespace approved for allocation", err)
	}
	if _, err = d.pool.Exec(t.Context(), `INSERT INTO control.local_project_services(team_id,project_key,source_fingerprint,service,worktree_key,public_url_id,created_by_identity_id) VALUES($1,'equipment',$2,'localapp','worktree',$3,$4)`, base.TeamID, r.SourceFingerprint, base.PublicURLID, base.ActingIdentityID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Resource: base.PublicURLID, ExpiresAt: now.Add(time.Hour)}, base.ActingIdentityID, now); err != nil {
		t.Fatal("local project metadata incorrectly prohibited publication", err)
	}
	exchange, _ := publicationExchange(t, f, base.PublicURLID, "")
	session, err := d.ExchangeMachinePublication(t.Context(), exchange, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
	if err != nil {
		t.Fatal(err)
	}
	// moving the same record into a remote publisher group must fence already
	// issued tokens as well as future exchanges, not just manager approval.
	if _, err = d.pool.Exec(t.Context(), `INSERT INTO control.applied_project_services(team_id,project_key,service,group_id,public_url_id,desired_revision) VALUES($1,'equipment','remapped',$2,$3,1)`, base.TeamID, applied.Groups[0].ID, base.PublicURLID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.AuthenticatePublisherAccess(t.Context(), session.AccessToken, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("existing publisher bypassed current remote authority", err)
	}
	if _, err = d.ExchangeMachinePublication(t.Context(), exchange, machineTestServer+"/v1/machine-publication-sessions/exchange", now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("exchange bypassed remote ownership", err)
	}
}

func TestIntegrationMachinePublicationCapturedGrantCannotExpand(t *testing.T) {
	d, now, base, _ := newPublishRunPrerequisites(t)
	f := publicationMachine(t, d, base.TeamID, base.ActingIdentityID, "signing_key", now)
	if _, err := d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Resource: base.PublicURLID, ExpiresAt: now.Add(time.Hour)}, base.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	r, key := publicationExchange(t, f, base.PublicURLID, "")
	session, err := d.ExchangeMachinePublication(t.Context(), r, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
	if err != nil {
		t.Fatal(err)
	}
	u := createTestPublicURL(t, d, CreatePublicURLRequest{TeamID: base.TeamID, DomainID: "domain_session", ActingIdentityID: base.ActingIdentityID, CanonicalHostname: "second.session.example.test", Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeShared, Purpose: PublicURLPurposeApp, IdempotencyKey: "second", DNSState: PublicURLDNSUnmanaged}, now)
	grant, err := d.CreatePublisherGrant(t.Context(), CreatePublisherGrantRequest{PublisherIdentityID: session.Publisher.ClientId, Scope: PublisherScope{TeamID: base.TeamID, Kind: "saved_public_url", PublicURLID: u.ID}, EditorID: base.ActingIdentityID, EditorMembershipID: base.MembershipID, PolicyRevision: base.PolicyRevision, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := publisherproof.Sign(session.Publisher.ClientId, session.Publisher.KeyId, grant, publisherTestAudience, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ExchangePublisherAssertion(t.Context(), session.Publisher.ClientId, grant, publisherTestAudience, proof, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("later approval widened an issued source session", err)
	}
	seedControlPublicURL(t, d, now, "foreign")
	if _, err = d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Resource: "public_url_foreign", ExpiresAt: now.Add(time.Hour)}, base.ActingIdentityID, now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("cross-team resource approved", err)
	}
	if _, err = d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Namespace: "foreign.example.test", DomainID: "domain_foreign", ExpiresAt: now.Add(time.Hour)}, base.ActingIdentityID, now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("cross-team namespace approved", err)
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	if err = d.RotateMachineIdentityKey(t.Context(), base.TeamID, f.machine.ID, base.ActingIdentityID, "second", public, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.AuthenticatePublisherAccess(t.Context(), session.AccessToken, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("source-key rotation left old publication authority", err)
	}
}

func shaFingerprint() string {
	return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

func TestIntegrationMachinePublicationDenialsAndSourceExpiry(t *testing.T) {
	d, now, base, _ := newPublishRunPrerequisites(t)
	f := publicationMachine(t, d, base.TeamID, base.ActingIdentityID, "signing_key", now)
	r, key := publicationExchange(t, f, base.PublicURLID, "")
	if _, err := d.ExchangeMachinePublication(t.Context(), r, machineTestServer+"/v1/machine-publication-sessions/exchange", now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("unapproved publication", err)
	}
	_, err := d.CreateMachinePublicationPermission(t.Context(), MachinePublicationPermission{MachineID: f.machine.ID, TeamID: base.TeamID, Resource: base.PublicURLID, ExpiresAt: now.Add(time.Hour)}, base.ActingIdentityID, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*MachinePublicationExchange){"resource": func(r *MachinePublicationExchange) { r.Resource = "other" }, "namespace": func(r *MachinePublicationExchange) { r.Resource = ""; r.Namespace = "other.example.test" }, "key": func(r *MachinePublicationExchange) { r.PublicKey, _, _ = ed25519.GenerateKey(rand.Reader) }, "nonce": func(r *MachinePublicationExchange) { r.Nonce = rand.Text() }, "machine": func(r *MachinePublicationExchange) { r.MachineID = "other" }} {
		t.Run(name, func(t *testing.T) {
			bad := r
			edit(&bad)
			if _, err := d.ExchangeMachinePublication(t.Context(), bad, machineTestServer+"/v1/machine-publication-sessions/exchange", now); !errors.Is(err, ErrMachineDenied) {
				t.Fatal("wrong publication scope accepted", err)
			}
		})
	}
	if _, err = d.ExchangeMachinePublication(t.Context(), r, "https://other.example/exchange", now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("wrong audience accepted", err)
	}
	session, err := d.ExchangeMachinePublication(t.Context(), r, machineTestServer+"/v1/machine-publication-sessions/exchange", now)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(r.PublicKey)
	at := now.Add(time.Minute)
	proof := f.publicationProof(t, r.Resource, "", "refresh", encoded, session.Id, machineTestServer+"/v1/machine-publication-sessions/"+session.Id+"/refresh", at)
	digest := sha256.Sum256([]byte(proof.Assertion))
	signature := ed25519.Sign(key, machineproof.PublicationPossession(r.Resource, "", "refresh", encoded, session.Id, digest))
	if _, err = d.RefreshMachinePublication(t.Context(), session.Id, proof, signature, machineTestServer+"/v1/machine-publication-sessions/"+session.Id+"/refresh", at); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("expired source resurrected", err)
	}
	if _, err = d.ExchangePublisherAssertion(t.Context(), session.Publisher.ClientId, session.Publisher.GrantId, publisherTestAudience, "invalid", "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("machine bypassed source proof", err)
	}
	if _, err = d.CleanupWorkloads(t.Context(), now.Add(WorkloadHistoryRetention+time.Hour), 1); err != nil {
		t.Fatal(err)
	}
	if _, err = d.AuthenticatePublisherAccess(t.Context(), session.AccessToken, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("cleanup detached machine authority", err)
	}
}
