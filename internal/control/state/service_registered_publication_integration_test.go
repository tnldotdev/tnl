package state

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func registeredServicePublisher(t *testing.T, d *Database, request ApplyProjectConfigurationRequest, now time.Time, capability string) (DeploymentCredential, PublisherAccess, DeploymentScope) {
	t.Helper()
	editor := DeploymentScope{TeamID: request.TeamID, ProjectKey: request.ProjectKey, ActorID: request.ActorID}
	deployment, err := d.GetDeployment(t.Context(), editor, "production")
	if err != nil {
		t.Fatal(err)
	}
	registration, private := managementRegistration(t, editor, now)
	registration.Permissions = map[string][]string{capability: {"app"}}
	registration.AllDeployments, registration.DeploymentIDs = false, []string{deployment.ID}
	credential, err := d.RegisterDeploymentCredential(t.Context(), registration)
	if err != nil {
		t.Fatal(err)
	}
	access := managementAccess(t, d, credential, private, now)
	return credential, access, DeploymentScope{TeamID: request.TeamID, ProjectKey: request.ProjectKey, AccessToken: access.Token}
}

func TestIntegrationRegisteredServicePendingAdmissionRechecksPermission(t *testing.T) {
	for _, mutation := range []string{"approval", "key", "service-deadline"} {
		t.Run(mutation, func(t *testing.T) {
			d, now, request, _, service := serviceReleaseProject(t, "http", false)
			credential, access, _ := registeredServicePublisher(t, d, request, now, "publish")
			ctx := t.Context()
			prepared, err := d.PrepareServiceRun(ctx, service.ID, access.PublisherIdentity, "pending-admission", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
			if err != nil {
				t.Fatal(err)
			}
			run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
			if err != nil {
				t.Fatal(err)
			}
			installPrivateTestCertificate(t, d, prepared, run, now)
			for _, slot := range run.Connections {
				lease := RelayLeaseIdentity{RelayServiceID: slot.RelayServiceID}
				if err := d.pool.QueryRow(ctx, `SELECT relay_id,relay_run_id,relay_lease_revision FROM control.relay_leases WHERE relay_service_id=$1`, slot.RelayServiceID).Scan(&lease.RelayID, &lease.RelayRunID, &lease.RelayLeaseRevision); err != nil {
					t.Fatal(err)
				}
				if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, now); err != nil {
					t.Fatal(err)
				}
				if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
					t.Fatal(err)
				}
			}
			if state, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
				t.Fatal("registered service is not ready", err)
			}
			ingress, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "registered-pending", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), ProtocolVersion: 1, HTTPS: true, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID}, now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			read := func() (IngressServiceRun, error) {
				return readIngressServiceRun(ctx, d, ingress.IngressLeaseIdentity, service.ID, run.RunID, now)
			}
			first, err := read()
			if err != nil || first.RunID != run.RunID {
				t.Fatal("first admission failed", err)
			}
			deadline := now.Truncate(time.Microsecond).Add(5 * time.Second)
			switch mutation {
			case "approval":
				_, err = d.pool.Exec(ctx, `UPDATE control.deployment_management_services SET revoked_at=$2 WHERE grant_id=$1 AND capability='publish'`, credential.GrantID, now)
			case "key":
				_, err = d.pool.Exec(ctx, `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=$1`, credential.KeyID, now)
			case "service-deadline":
				_, err = d.pool.Exec(ctx, `UPDATE control.services SET expires_at=$2 WHERE id=$1`, service.ID, deadline)
			}
			if err != nil {
				t.Fatal(err)
			}
			retry, err := read()
			if mutation == "service-deadline" {
				if err != nil || !retry.ValidUntil.Equal(deadline) || !retry.ValidUntil.Before(first.ValidUntil) {
					t.Fatal("pending retry ignored the current fixed service deadline", err)
				}
			} else if !errors.Is(err, ErrServiceAccess) {
				t.Fatal("stored pending visitor bypassed current publisher permission", err)
			}
		})
	}
}

func TestIntegrationRegisteredServicePublicationRetainsGrantDeadlineAndExactCertificate(t *testing.T) {
	d, now, request, _, service := serviceReleaseProject(t, "http", false)
	credential, access, scope := registeredServicePublisher(t, d, request, now, "publish")
	ctx := t.Context()
	deadline := now.Truncate(time.Microsecond).Add(10 * time.Second)
	if _, err := d.pool.Exec(ctx, `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, credential.GrantID, deadline); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1`, credential.ClientID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	selected, err := d.GetDeploymentPublication(ctx, scope, "production", "app", now)
	if err != nil || selected.ID != service.ID {
		t.Fatal("named selection did not return the ordinary service", err)
	}
	prepared, err := d.PrepareServiceRun(ctx, selected.ID, access.PublisherIdentity, "registered-attempt", now, ServiceRunRequest{Metadata: selected.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.PublisherGrantID != credential.GrantID || prepared.PublisherKeyID != credential.KeyID ||
		prepared.PublisherIdentityID != credential.ClientID || !prepared.ExpiresAt.Equal(deadline) ||
		prepared.CertificatePlan.Scope != service.Endpoint.Hostname ||
		!slices.Equal(prepared.CertificatePlan.Identifiers, []string{service.Endpoint.Hostname}) {
		t.Fatal("preparation changed the original grant, deadline, or exact-host certificate plan")
	}
	recovered, err := d.PrepareServiceRun(ctx, selected.ID, access.PublisherIdentity, "registered-attempt", now, ServiceRunRequest{Metadata: selected.ServiceMetadata})
	if err != nil || recovered.RunID != prepared.RunID || recovered.RunNumber != prepared.RunNumber || !recovered.ExpiresAt.Equal(deadline) {
		t.Fatal("preparation retry changed the run or extended permission", err)
	}
	run, err := d.StartServiceRun(ctx, selected.ID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
	if err != nil || !run.ExpiresAt.Equal(deadline) {
		t.Fatal("start outlived the fixed registered grant", err)
	}
	renewed, err := d.HeartbeatServiceRun(ctx, selected.ID, run.RunID, run.Token, now.Add(time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 1})
	if err != nil || !renewed.ExpiresAt.Equal(deadline) {
		t.Fatal("renewal extended the registered grant deadline", err)
	}
	var after int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1`, credential.ClientID).Scan(&after); err != nil || after != before {
		t.Fatal("registered publication created child grants", err)
	}
	if err := d.RevokePublisherGrant(ctx, request.TeamID, credential.ClientID, credential.GrantID, request.ActorID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err := controlstatedb.New(d.pool).LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: run.RunID, ServiceID: selected.ID})
	if err != nil || !stored.ClosedAt.Valid || stored.PublisherGrantID != credential.GrantID {
		t.Fatal("root grant revocation did not close its ordinary run", err)
	}
}

func TestIntegrationRegisteredServicePublicationCapabilityAndEndpointIndependence(t *testing.T) {
	for _, capability := range []string{"manage", "connect", "publish"} {
		t.Run(capability, func(t *testing.T) {
			d, now, request, _, service := serviceReleaseProject(t, "http", false)
			_, access, scope := registeredServicePublisher(t, d, request, now, capability)
			selected, err := d.GetDeploymentPublication(t.Context(), scope, "production", "app", now)
			if capability != "publish" {
				if err == nil || selected.ID != "" {
					t.Fatal("another capability implied publication")
				}
				return
			}
			if err != nil || selected.ID != service.ID {
				t.Fatal(err)
			}
			// endpoint visibility never grants or removes publication permission.
			if _, err := d.pool.Exec(t.Context(), `UPDATE control.services SET public=false WHERE id=$1`, service.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := d.GetServiceForPublisher(t.Context(), service.ID, access.PublisherIdentity, now); err != nil {
				t.Fatal("connector-only service lost publication permission", err)
			}
			tx, err := d.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, tx)
			if _, err := deploymentConnectAuthority(t.Context(), tx, access.GrantID, access.KeyID, service.ID, now); err == nil {
				t.Fatal("publish implied connector access")
			}
			if _, err := d.GetDeployment(t.Context(), scope, "production"); !errors.Is(err, ErrDeploymentAccess) {
				t.Fatal("publish implied management", err)
			}
		})
	}
}

func TestIntegrationRegisteredServicePermissionRetirementAndKeyChecks(t *testing.T) {
	for _, mutation := range []string{"identity", "grant", "key", "protocol-rollback"} {
		t.Run(mutation, func(t *testing.T) {
			d, now, request, _, service := serviceReleaseProject(t, "http", false)
			credential, access, scope := registeredServicePublisher(t, d, request, now, "publish")
			ctx := t.Context()
			switch mutation {
			case "identity":
				_, err := d.pool.Exec(ctx, `UPDATE control.publisher_identities SET revoked_at=$2 WHERE id=$1`, credential.ClientID, now)
				if err != nil {
					t.Fatal(err)
				}
			case "grant":
				_, err := d.pool.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, credential.GrantID, now)
				if err != nil {
					t.Fatal(err)
				}
			case "key":
				_, err := d.pool.Exec(ctx, `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=$1`, credential.KeyID, now)
				if err != nil {
					t.Fatal(err)
				}
			case "protocol-rollback":
				for _, protocol := range []string{"tcp", "http"} {
					if _, err := d.pool.Exec(ctx, `UPDATE control.project_services SET protocol=$3 WHERE team_id=$1 AND project_key=$2 AND name='app'`, request.TeamID, request.ProjectKey, protocol); err != nil {
						t.Fatal(err)
					}
				}
			}
			if selected, err := d.GetDeploymentPublication(ctx, scope, "production", "app", now); err == nil || selected.ID != "" {
				t.Fatal("named selection retained retired authority")
			}
			if _, err := d.GetServiceForPublisher(ctx, service.ID, access.PublisherIdentity, now); err == nil {
				t.Fatal("explicit service read bypassed current permission")
			}
		})
	}
}

func TestIntegrationRegisteredServiceSelectionRechecksAfterLockWait(t *testing.T) {
	for _, mutation := range []string{"identity", "grant", "key", "deadline"} {
		t.Run(mutation, func(t *testing.T) {
			d, now, request, _, _ := serviceReleaseProject(t, "http", false)
			credential, _, scope := registeredServicePublisher(t, d, request, now, "publish")
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockLocalTeamForMutation(ctx, request.TeamID); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			if mutation == "deadline" {
				if _, err := gate.Exec(ctx, `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, credential.GrantID, now.Add(150*time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			workers.Go(func() {
				selected, err := d.GetDeploymentPublication(ctx, scope, "production", "app", now)
				if selected.ID != "" {
					err = errors.Join(err, errors.New("denied read returned service"))
				}
				done <- err
			})
			waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			switch mutation {
			case "identity":
				_, err = gate.Exec(ctx, `UPDATE control.publisher_identities SET revoked_at=$2 WHERE id=$1`, credential.ClientID, now)
			case "grant":
				_, err = gate.Exec(ctx, `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, credential.GrantID, now)
			case "key":
				_, err = gate.Exec(ctx, `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=$1`, credential.KeyID, now)
			case "deadline":
				timer := time.NewTimer(max(0, time.Until(started.Add(250*time.Millisecond))))
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
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, done); err == nil {
				t.Fatal("waiting selection escaped current permission")
			}
		})
	}
}
