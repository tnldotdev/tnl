package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type deploymentConnectFixture struct {
	d           *Database
	now         time.Time
	project     ApplyProjectConfigurationRequest
	setup       CreateDeploymentPublisherEnrollmentRequest
	deployment  Deployment
	run         ServiceRunState
	publisherID string
	leases      map[string]RelayLease
}

func TestIntegrationDeploymentConnectAuthorityAfterLockWait(t *testing.T) {
	for _, boundary := range []string{"identity", "grant", "key", "declaration", "deadline"} {
		t.Run(boundary, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "deployment_connect_wait_"+boundary)
			_, setup := deploymentPublisherRequest(t, d, now)
			deployment, err := d.GetDeployment(t.Context(), setup.DeploymentScope, "production")
			if err != nil {
				t.Fatal(err)
			}
			request, private := managementRegistration(t, setup.DeploymentScope, now)
			request.Permissions = map[string][]string{"connect": {"db"}}
			credential, err := d.RegisterDeploymentCredential(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			access := managementAccess(t, d, credential, private, now)
			if err = d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err = controlstatedb.New(gate).LockLocalTeamForMutation(ctx, request.TeamID); err != nil {
				t.Fatal(err)
			}
			if boundary == "deadline" {
				if _, err = gate.Exec(ctx, `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, credential.GrantID, now.Add(250*time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			started := time.Now()
			workers.Go(func() {
				issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, visitorscope.Scope{Kind: visitorscope.Service, ID: deployment.Services["db"].ID}, RegisteredKeyTokenSource{Credential: access.Token}, now)
				if err != nil && issued.Token.Reveal() != "" {
					err = errors.Join(err, errors.New("denied preparation returned a token"))
				}
				done <- err
			})
			waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			switch boundary {
			case "identity":
				_, err = gate.Exec(ctx, `UPDATE control.publisher_identities SET revoked_at=$2 WHERE id=$1`, credential.ClientID, now)
			case "grant":
				_, err = gate.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, credential.GrantID, now)
			case "key":
				_, err = gate.Exec(ctx, `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=$1`, credential.KeyID, now)
			case "declaration":
				_, err = gate.Exec(ctx, `UPDATE control.project_services SET protocol='mysql' WHERE team_id=$1 AND project_key=$2 AND name='db'`, request.TeamID, request.ProjectKey)
			case "deadline":
				// spend the fixed authority deadline, not a readiness delay.
				timer := time.NewTimer(max(0, time.Until(started.Add(350*time.Millisecond))))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(context.Cause(ctx))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrVisitorPermission) && !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("waiting visitor escaped current authority", err)
			}
		})
	}
}

func newDeploymentConnectFixture(t *testing.T) deploymentConnectFixture {
	t.Helper()
	d, now, _, leases := newConnectorPairPrerequisites(t)
	project, setup := deploymentPublisherRequest(t, d, now)
	deployment, err := d.GetDeployment(t.Context(), setup.DeploymentScope, "production")
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.CreateDeploymentPublisherEnrollment(t.Context(), setup)
	if err != nil {
		t.Fatal(err)
	}
	publisher := enrollAppliedDeployment(t, d, project, enrollment, now)
	assignment := publisher.assignments.Services[0]
	access := deploymentAssignmentAccess(t, d, publisher, assignment, now)
	prepared, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "deployment-connect", now, ServiceMetadata{Protocol: "postgres", PublisherPool: true, TrustRevision: assignment.TrustRevision})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, prepared, run, now)
	for _, slot := range run.Connections {
		lease := leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err = d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, assignment.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err = d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = d.HeartbeatServiceRun(t.Context(), assignment.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	return deploymentConnectFixture{d, now, project, setup, deployment, run, access.PublisherIdentity.ID, leases}
}

func TestIntegrationDeploymentConnectIndependentCapabilities(t *testing.T) {
	f := newDeploymentConnectFixture(t)
	d, now, ctx := f.d, f.now, t.Context()
	request, private := managementRegistration(t, f.setup.DeploymentScope, now)
	request.AllDeployments, request.DeploymentIDs = false, []string{f.deployment.ID}
	service := f.deployment.Services["db"].ID
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service}
	if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	for _, capability := range []string{"manage", "connect", "combined"} {
		t.Run(capability, func(t *testing.T) {
			r := request
			r.IdempotencyKey = capability
			switch capability {
			case "manage":
				r.Permissions = map[string][]string{"manage": {"db"}}
			case "connect":
				r.Permissions = map[string][]string{"connect": {"db"}}
			case "combined":
				r.Permissions = map[string][]string{"manage": {"web"}, "connect": {"db"}}
			}
			credential, err := d.RegisterDeploymentCredential(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := d.RegisterDeploymentCredential(ctx, r)
			if err != nil || !reflect.DeepEqual(recovered, credential) {
				t.Fatal("recovery changed capability, key or deadline", err)
			}
			access := managementAccess(t, d, credential, private, now)
			management := DeploymentScope{TeamID: request.TeamID, ProjectKey: request.ProjectKey, AccessToken: access.Token}
			read, managementErr := d.GetDeployment(ctx, management, "production")
			if capability == "connect" {
				if !errors.Is(managementErr, ErrDeploymentAccess) {
					t.Fatal("connect implied management", managementErr)
				}
				setup := f.setup
				setup.DeploymentScope = management
				denied, err := d.CreateDeploymentPublisherEnrollment(ctx, setup)
				if !errors.Is(err, ErrDeploymentAccess) || denied.Key != "" {
					t.Fatal("connect created publisher authority or returned a secret", err)
				}
			} else if managementErr != nil || len(read.Services) != 1 || capability == "combined" && read.Services["web"].ID == "" {
				t.Fatal("management did not retain its own allowlist", managementErr)
			}
			source := RegisteredKeyTokenSource{Credential: access.Token}
			issued, connectErr := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, source, now)
			if capability == "manage" {
				if !errors.Is(connectErr, ErrVisitorPermission) {
					t.Fatal("management implied connect", connectErr)
				}
				return
			}
			if connectErr != nil {
				t.Fatal(connectErr)
			}
			registered, ok := issued.Permission.Subject.(visitortoken.RegisteredKey)
			if !ok || registered.GrantID != credential.GrantID || registered.KeyID != credential.KeyID || issued.Permission.ExpiresAt.After(credential.ExpiresAt) {
				t.Fatal("permission lost exact key, grant or fixed deadline")
			}
			selected, err := d.SelectDeploymentServiceRun(ctx, request.TeamID, request.ProjectKey, f.deployment.ID, "db", source, now)
			if err != nil || selected.ServiceID != service || selected.ServiceRunID != f.run.RunID || selected.Endpoint == nil {
				t.Fatal("approved deployment service did not select its run", err)
			}
			for _, denied := range []struct{ project, deployment, service string }{
				{request.ProjectKey, "staging", "stage"}, {request.ProjectKey, f.deployment.ID, "web"}, {"other-project", f.deployment.ID, "db"},
			} {
				if result, err := d.SelectDeploymentServiceRun(ctx, request.TeamID, denied.project, denied.deployment, denied.service, source, now); err == nil || result.ServiceID != "" {
					t.Fatal("connect escaped captured selection", denied, err)
				}
			}
			if _, err = d.GetServiceForPublisher(ctx, service, access.PublisherIdentity, now); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("connect implied publish", err)
			}
		})
	}
}

func TestIntegrationDeploymentConnectExplicitFutureDeploymentApproval(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "deployment_connect_future")
	_, setup := deploymentPublisherRequest(t, d, now)
	production, err := d.GetDeployment(t.Context(), setup.DeploymentScope, "production")
	if err != nil {
		t.Fatal(err)
	}
	request, private := managementRegistration(t, setup.DeploymentScope, now)
	request.Permissions = map[string][]string{"manage": {"db"}, "connect": {"db"}}
	broad, err := d.RegisterDeploymentCredential(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	broadAccess := managementAccess(t, d, broad, private, now)
	narrowRequest := request
	narrowRequest.IdempotencyKey, narrowRequest.AllDeployments, narrowRequest.DeploymentIDs = "narrow", false, []string{production.ID}
	narrow, err := d.RegisterDeploymentCredential(t.Context(), narrowRequest)
	if err != nil {
		t.Fatal(err)
	}
	narrowAccess := managementAccess(t, d, narrow, private, now)
	runtime := DeploymentScope{TeamID: request.TeamID, ProjectKey: request.ProjectKey, AccessToken: broadAccess.Token}
	created, err := d.CreateDeployment(t.Context(), CreateDeploymentRequest{DeploymentScope: runtime, Name: "customer", IdempotencyKey: "create", Targets: map[string]DeploymentTarget{"db": {Address: "customer.internal:5432"}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err = d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: created.Services["db"].ID}
	if _, err = d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, RegisteredKeyTokenSource{Credential: narrowAccess.Token}, now); !errors.Is(err, ErrVisitorPermission) {
		t.Fatal("exact approval expanded to a future deployment", err)
	}
	if _, err = d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, RegisteredKeyTokenSource{Credential: broadAccess.Token}, now); err != nil {
		t.Fatal("explicit future approval could not connect", err)
	}
	if err = d.DeleteDeployment(t.Context(), runtime, created.ID, created.Revision, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, RegisteredKeyTokenSource{Credential: broadAccess.Token}, now); err == nil {
		t.Fatal("deleted deployment retained connect authority")
	}
	request.Now = broad.ExpiresAt
	if _, err = d.RegisterDeploymentCredential(t.Context(), request); !errors.Is(err, ErrDeploymentCredentialUnavailable) {
		t.Fatal("recovery extended expired approval", err)
	}
}

func TestIntegrationDeploymentConnectRetainedOwnerAndRevocation(t *testing.T) {
	f := newDeploymentConnectFixture(t)
	d, now, ctx := f.d, f.now, t.Context()
	request, private := managementRegistration(t, f.setup.DeploymentScope, now)
	request.Permissions = map[string][]string{"manage": {"db"}, "connect": {"db"}}
	credential, err := d.RegisterDeploymentCredential(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	access := managementAccess(t, d, credential, private, now)
	source := RegisteredKeyTokenSource{Credential: access.Token}
	service := f.deployment.Services["db"].ID
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service}
	if err = d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, source, now)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := visitortoken.ConnectorSubject(issued.Permission.Subject)
	if err != nil {
		t.Fatal(err)
	}
	pairRequest := ConnectorPeerPairRequest{ServiceID: service, ServiceRunID: f.run.RunID, RunNumber: f.run.RunNumber,
		PublisherIdentityID: f.publisherID, Subject: subject, Source: source, Action: "create", IdempotencyKey: "registered-owner", RequestedAt: now, ExpectedRelays: testConnectorPairRelays(f.run, f.leases)}
	signConnectorPairRequest(t, &pairRequest, private)
	pair, err := d.PrepareConnectorPeerPair(ctx, pairRequest, now)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := d.PrepareConnectorPeerPair(ctx, pairRequest, now)
	if err != nil || recovered.ID != pair.ID || recovered.Key != pair.Key || !recovered.ExpiresAt.Equal(pair.ExpiresAt) {
		t.Fatal("owner retry changed key or deadline", err)
	}
	t.Run("independent stable owners", func(t *testing.T) { assertNativeStateStableOwners(t, d, ctx, pairRequest, private, f.run, now) })
	for slot := range pair.Relays {
		proof := testConnectorLegProof(t, pair, slot, now, private)
		if _, err = testClaimConnectorPeerPairLeg(t, d, ctx, pair.Relays[slot].RelayLease, netip.MustParseAddr("192.0.2.10"), proof, now); err != nil {
			t.Fatal("registered key did not claim exact relay leg", err)
		}
	}
	at := now.Add(time.Second)
	if _, err = d.DeliverConnectorPeerPair(ctx, service, f.run.RunID, pair.ID, pair.DeliveryGeneration, f.run.Token, at); err != nil {
		t.Fatal("retained registered-key subject could not deliver", err)
	}
	lease, err := visitorlease.New(scope, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	applyPolicy := func() {
		t.Helper()
		wire, err := d.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, at)
		if err != nil {
			t.Fatal(err)
		}
		update, err := visitorlease.Decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err = lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
	}
	applyPolicy()
	view, _, _ := lease.Current()
	entry := tunnelv1.ConnectorPeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorPeerVisitorStream,
		PairID: pair.ID, DeliveryID: base64.RawURLEncoding.EncodeToString(pair.DeliveryID[:]), DeliveryGeneration: pair.DeliveryGeneration, ServiceID: service, ServiceRunID: f.run.RunID, RunNumber: uint64(f.run.RunNumber), Subject: subject,
		SourceIP: "192.0.2.10", VisitorConnectionID: mustOpaqueID(t, "vc_"), MetadataRevision: uint64(view.MetadataRevision),
		Permission: tunnelv1.ConnectorVisitorPermission{Token: issued.Token.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}}
	message, err := tunnelv1.ConnectorPeerProofMessage(entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	expected := entry.Session()
	expected.ExpiresAt = pair.ExpiresAt
	verified, err := visitortoken.VerifyConnectorPeerSession(entry, nil, expected, view, at)
	if err != nil {
		t.Fatal(err)
	}
	var stopped atomic.Int32
	guard, err := lease.BindConnector(verified, netip.MustParseAddr(entry.SourceIP), int64(entry.MetadataRevision), func() { stopped.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err = guard.AllowRenewal(); err != nil {
		t.Fatal(err)
	}
	before := connectorPairSavedAuthority(t, d, pair.ID)
	if err = d.RevokePublisherGrant(ctx, request.TeamID, credential.ClientID, credential.GrantID, request.ActorID, at); err != nil {
		t.Fatal(err)
	}
	if _, err = d.DeliverConnectorPeerPair(ctx, service, f.run.RunID, pair.ID, pair.DeliveryGeneration, f.run.Token, at); err == nil {
		t.Fatal("revoked key retained delivery authority")
	}
	if _, err = d.PrepareConnectorPeerPair(ctx, pairRequest, at); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("creation retry restored revoked authority", err)
	}
	if after := connectorPairSavedAuthority(t, d, pair.ID); !bytes.Equal(before, after) {
		t.Fatal("denied recovery mutated retained owner")
	}
	applyPolicy()
	if _, err = guard.Current(); err == nil || stopped.Load() != 1 {
		t.Fatal("policy refresh did not close retained registered-key stream", err)
	}
	if _, err = d.HeartbeatServiceRun(ctx, service, f.run.RunID, f.run.Token, at, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("backend revocation revoked independently enrolled publisher", err)
	}
}
