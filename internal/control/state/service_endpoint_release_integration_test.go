package state

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func serviceReleaseProject(t *testing.T, protocol string, automation bool) (*Database, time.Time, ApplyProjectConfigurationRequest, AppliedProjectConfiguration, ServiceRecord) {
	t.Helper()
	d, now, _, _ := newPublishRunPrerequisites(t)
	if err := d.ConfigureIngressServicePorts(t.Context(), PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25444}}); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.DNSAutomation = automation
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"app": {Protocol: protocol, Target: "localhost:3000", Public: new(true)},
	}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.GetService(t.Context(), applied.Services[0].ServiceID, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	return d, now, r, applied, service
}

func setReleaseProjectExposure(t *testing.T, d *Database, r *ApplyProjectConfigurationRequest, applied *AppliedProjectConfiguration, public bool) {
	t.Helper()
	r.ExpectedRevision = applied.Revision
	binding := r.Configuration.Services["app"]
	binding.Public = new(public)
	r.Configuration.Services["app"] = binding
	var err error
	*applied, err = d.ApplyProjectConfiguration(t.Context(), *r)
	if err != nil {
		t.Fatal(err)
	}
}

func serviceReleasePublisher(t *testing.T, d *Database, r ApplyProjectConfigurationRequest, now time.Time) PublisherIdentity {
	t.Helper()
	enrollment, err := testDeploymentPublisherEnrollment(d, t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, enrollment, now)
	return deploymentAssignmentAccess(t, d, replica, replica.assignments.Services[0], now).PublisherIdentity
}

func TestIntegrationServiceEndpointReleasePreservesServiceAndHistoricalClaims(t *testing.T) {
	for _, protocol := range []string{"http", "postgres"} {
		t.Run(protocol, func(t *testing.T) {
			d, now, r, applied, service := serviceReleaseProject(t, protocol, false)
			ctx := t.Context()
			if _, err := d.ReleaseServiceEndpoint(ctx, service.ID, r.ActorID, service.TrustRevision, service.Endpoint.Port, now); !errors.Is(err, ErrServiceEndpointPublic) {
				t.Fatal("release silently disabled exposure", err)
			}
			setReleaseProjectExposure(t, d, &r, &applied, false)
			publisher := serviceReleasePublisher(t, d, r, now)
			prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "before-release", now, service.ServiceMetadata)
			if err != nil {
				t.Fatal(err)
			}
			run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
			if err != nil {
				t.Fatal(err)
			}
			for _, bad := range []struct {
				actor    string
				revision int64
				port     int
				want     error
			}{
				{"identity-unrelated", service.TrustRevision, service.Endpoint.Port, ErrServiceAccess},
				{r.ActorID, service.TrustRevision + 1, service.Endpoint.Port, ErrServiceConflict},
				{r.ActorID, service.TrustRevision, 25445, ErrServiceConflict},
				{r.ActorID, service.TrustRevision, 0, ErrServiceConflict},
			} {
				if _, err := d.ReleaseServiceEndpoint(ctx, service.ID, bad.actor, bad.revision, bad.port, now); !errors.Is(err, bad.want) {
					t.Fatal("release accepted another actor or binding", err)
				}
			}
			released, err := d.ReleaseServiceEndpoint(ctx, service.ID, r.ActorID, service.TrustRevision, service.Endpoint.Port, now)
			if err != nil || released.ID != service.ID || released.Endpoint == nil || released.Endpoint.Hostname != service.Endpoint.Hostname ||
				released.Endpoint.Port != 0 || released.Endpoint.Public || released.TrustRevision != service.TrustRevision+1 {
				t.Fatal("release replaced service identity or failed to fence the binding", released, err)
			}
			if _, err := d.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 1}); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("old run survived release", err)
			}
			if _, err := d.PrepareServiceRun(ctx, service.ID, publisher, "stale-metadata", now, service.ServiceMetadata); !errors.Is(err, ErrServiceConflict) {
				t.Fatal("old trust revision prepared another run", err)
			}
			private, err := d.PrepareServiceRun(ctx, service.ID, publisher, "after-release", now, released.ServiceMetadata)
			if err != nil || private.ServicePort != 0 || private.RunNumber <= prepared.RunNumber {
				t.Fatal("release revoked the publisher grant or zero-port binding", private, err)
			}
			privateRun, err := d.StartServiceRun(ctx, service.ID, private.RunID, private.RunNumber, publisher, now)
			if err != nil {
				t.Fatal("private publication did not resume", err)
			}
			var visitorGrants int
			if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.visitor_grants WHERE service_id=$1 AND revoked_at IS NULL`, service.ID).Scan(&visitorGrants); err != nil || visitorGrants != 1 {
				t.Fatal("release changed visitor grants", visitorGrants, err)
			}
			if count, err := d.ReleaseServicePorts(ctx, now.Add(6*24*time.Hour)); err != nil || count != 0 {
				t.Fatal("release skipped the minimum quarantine", count, err)
			}
			// later private authority is independent of the retired reservation.
			futureOrder := serviceReleaseIssuance(t, d, private, privateRun, now)
			if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET publisher_expires_at=$2,certificate_expires_at=$3,certificate_issuance_id=$4 WHERE id=$1`, private.RunID, now.Add(30*24*time.Hour), now.Add(90*24*time.Hour), futureOrder.ID); err != nil {
				t.Fatal(err)
			}
			setReleaseProjectExposure(t, d, &r, &applied, true)
			next, err := d.GetService(ctx, service.ID, r.ActorID)
			if err != nil || next.Endpoint.Port == service.Endpoint.Port || next.Endpoint.Hostname != service.Endpoint.Hostname || next.TrustRevision != released.TrustRevision+1 {
				t.Fatal("new reservation reused quarantined authority", next, err)
			}
			if _, err := d.ReleaseServiceEndpoint(ctx, service.ID, r.ActorID, service.TrustRevision, service.Endpoint.Port, now); !errors.Is(err, ErrServiceConflict) {
				t.Fatal("delayed release retired a replacement reservation", err)
			}
			if count, err := d.ReleaseServicePorts(ctx, now.Add(8*24*time.Hour)); err != nil || count != 1 {
				t.Fatal("future private certificate pinned historical capacity", count, err)
			}
			var claims, held, releasedClaims int
			if err := d.pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE state='held'),count(*) FILTER(WHERE state='released') FROM control.service_port_claims WHERE service_id=$1`, service.ID).Scan(&claims, &held, &releasedClaims); err != nil || claims != 2 || held != 1 || releasedClaims != 1 {
				t.Fatal("historical reservation was lost or confused with current authority", claims, held, releasedClaims, err)
			}
			// the old port can now be assigned to another service, without giving
			// the retired service's credentials authority over that new identity.
			r.ExpectedRevision = applied.Revision
			binding := r.Configuration.Services["app"]
			r.Configuration.Services["other"] = binding
			r.ServiceDeclarations["other"] = protocol
			reused, err := d.ApplyProjectConfiguration(ctx, r)
			if err != nil || reused.Services[1].ServiceID == service.ID || reused.Services[1].Port != service.Endpoint.Port {
				t.Fatal("settled historical capacity could not be reassigned", reused, err)
			}
		})
	}
}

func TestIntegrationLocalServiceEndpointReleaseRetainsCapturedIdentity(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := appliedProjectRequest(t, d, now)
	request := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "app", WorktreeKey: "checkout",
		ActorID: r.ActorID, Configuration: ProjectServiceConfiguration{Target: "app", Public: new(true)}, Now: now}
	first, err := d.RealizeLocalProjectService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Configuration.Public = new(false)
	private, err := d.RealizeLocalProjectService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	released, err := d.ReleaseServiceEndpoint(t.Context(), first.ServiceID, r.ActorID, private.Metadata.TrustRevision, private.Metadata.Endpoint.Port, now)
	if err != nil || released.Endpoint.Hostname != first.Metadata.Endpoint.Hostname || released.Endpoint.Port != 0 ||
		released.Source == nil || released.Source.ProjectKey != r.ProjectKey || released.Source.WorktreeKey != request.WorktreeKey {
		t.Fatal("local release lost captured endpoint identity", released, err)
	}
	restarted, err := d.RealizeLocalProjectService(t.Context(), request)
	if err != nil || restarted.ServiceID != first.ServiceID || restarted.Metadata.Endpoint.Port != 0 || restarted.Metadata.TrustRevision != released.TrustRevision {
		t.Fatal("local restart resurrected the retired reservation", restarted, err)
	}
}

func TestIntegrationServiceEndpointReleaseRequiresSettledDNS(t *testing.T) {
	d, now, r, applied, service := serviceReleaseProject(t, "http", true)
	setReleaseProjectExposure(t, d, &r, &applied, false)
	release := func() error {
		_, err := d.ReleaseServiceEndpoint(t.Context(), service.ID, r.ActorID, service.TrustRevision, service.Endpoint.Port, now)
		return err
	}
	if err := release(); !errors.Is(err, ErrServiceEndpointDNSPending) {
		t.Fatal("release skipped the private DNS replacement", err)
	}
	work, found, err := d.ClaimServiceEndpointDNSWork(t.Context(), "release-dns", now, time.Minute)
	if err != nil || !found || work.Public {
		t.Fatal("private DNS work unavailable", work, found, err)
	}
	if err := release(); !errors.Is(err, ErrServiceEndpointDNSPending) {
		t.Fatal("in-flight DNS was treated as a completed receipt", err)
	}
	work.State, work.AvailableAt = PublicURLDNSPublished, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(t.Context(), work, now); err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveServiceEndpointDNSWork(t.Context(), work, now); !errors.Is(err, ErrDNSPublicURLWorkStale) {
		t.Fatal("old worker rewrote the release receipt", err)
	}
}

func TestIntegrationServiceEndpointReleaseQuarantineTracksLateIssuance(t *testing.T) {
	d, now, r, applied, service := serviceReleaseProject(t, "postgres", false)
	setReleaseProjectExposure(t, d, &r, &applied, false)
	ctx := t.Context()
	publisher := serviceReleasePublisher(t, d, r, now)
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "release-issuance", now, service.ServiceMetadata)
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	order := serviceReleaseIssuance(t, d, prepared, run, now)
	if _, err := d.ReleaseServiceEndpoint(ctx, service.ID, r.ActorID, service.TrustRevision, service.Endpoint.Port, now); err != nil {
		t.Fatal(err)
	}
	var retiredCSR []byte
	if err := d.pool.QueryRow(ctx, `SELECT csr_der FROM control.acme_orders WHERE id=$1`, order.ID).Scan(&retiredCSR); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateServiceCertificateIssuance(ctx, service.ID, run.RunID, run.Token, "https://acme.example.test/directory", "after-retirement", run.RunNumber, retiredCSR, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("retired run authorized a new issuance", err)
	}
	assertHeld := func(at time.Time) {
		t.Helper()
		if count, err := d.ReleaseServicePorts(ctx, at); err != nil || count != 0 {
			t.Fatal("unfinished old authority became reusable", count, err)
		}
	}
	assertHeld(now.Add(8 * 24 * time.Hour))
	// cancellation alone does not prove that a finalization never reached the ca.
	if _, err := d.pool.Exec(ctx, `UPDATE control.acme_orders SET state='canceled',finalization_possible=true WHERE id=$1`, order.ID); err != nil {
		t.Fatal(err)
	}
	assertHeld(now.Add(8 * 24 * time.Hour))
	if _, err := d.pool.Exec(ctx, `UPDATE control.acme_orders SET not_before=$2,not_after=$3 WHERE id=$1`, order.ID, now, now.Add(10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertHeld(now.Add(9 * 24 * time.Hour))
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET certificate_expires_at=$2,certificate_issuance_id=$3 WHERE id=$1`, run.RunID, now.Add(11*24*time.Hour), order.ID); err != nil {
		t.Fatal(err)
	}
	assertHeld(now.Add(10 * 24 * time.Hour))
	if _, err := d.pool.Exec(ctx, `INSERT INTO control.acme_authorizations(id,order_id,identifier,authorization_url,challenge_type,challenge_url,challenge_token,challenge_digest,presentation_reference,state,available_at,presented_at,created_at,updated_at)
	    VALUES('release-auth',$1,'example.test','https://acme.example.test/auth','dns-01','https://acme.example.test/challenge','token',decode(repeat('00',32),'hex'),'release-presentation','canceled',$2,$2,$2,$2)`, order.ID, now); err != nil {
		t.Fatal(err)
	}
	assertHeld(now.Add(12 * 24 * time.Hour))
	if _, err := d.pool.Exec(ctx, `UPDATE control.acme_authorizations SET cleanup_completed_at=$1 WHERE id='release-auth'`, now.Add(12*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if count, err := d.ReleaseServicePorts(ctx, now.Add(12*24*time.Hour)); err != nil || count != 1 {
		t.Fatal("settled late authority kept capacity forever", count, err)
	}
}

func serviceReleaseIssuance(t *testing.T, d *Database, prepared ServiceRunPreparation, run ServiceRunState, now time.Time) CertificateIssuance {
	t.Helper()
	const directory = "https://acme.example.test/directory"
	if _, err := d.EnsureACMEAccount(t.Context(), directory, "operator@example.test", now); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: prepared.CertificatePlan.Identifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	order, err := d.CreateServiceCertificateIssuance(t.Context(), run.ServiceID, run.RunID, run.Token, directory, "release-csr", run.RunNumber, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	return order
}

func TestIntegrationServiceEndpointReleaseSerializesWithReenable(t *testing.T) {
	for _, releaseFirst := range []bool{false, true} {
		t.Run(map[bool]string{true: "release-first", false: "reenable-first"}[releaseFirst], func(t *testing.T) {
			d, now, r, applied, service := serviceReleaseProject(t, "http", false)
			setReleaseProjectExposure(t, d, &r, &applied, false)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockService(ctx, service.ID); err != nil {
				t.Fatal(err)
			}
			release, enable := make(chan error, 1), make(chan error, 1)
			startRelease := func() {
				workers.Go(func() {
					_, err := d.ReleaseServiceEndpoint(ctx, service.ID, r.ActorID, service.TrustRevision, service.Endpoint.Port, now)
					release <- err
				})
			}
			startEnable := func() {
				workers.Go(func() {
					r.ExpectedRevision = applied.Revision
					binding := r.Configuration.Services["app"]
					binding.Public = new(true)
					r.Configuration.Services["app"] = binding
					_, err := d.ApplyProjectConfiguration(ctx, r)
					enable <- err
				})
			}
			var pid int32
			if releaseFirst {
				startRelease()
				pid = waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), release)
				startEnable()
				waitForPostgresBlock(t, ctx, d, pid, enable)
			} else {
				startEnable()
				pid = waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), enable)
				startRelease()
				waitForPostgresBlock(t, ctx, d, pid, release)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			releaseErr, enableErr := awaitIntegrationResult(t, ctx, release), awaitIntegrationResult(t, ctx, enable)
			if enableErr != nil || releaseFirst && releaseErr != nil || !releaseFirst && !errors.Is(releaseErr, ErrServiceEndpointPublic) {
				t.Fatal("release and enable did not serialize", releaseErr, enableErr)
			}
			current, err := d.GetService(ctx, service.ID, r.ActorID)
			if err != nil || !current.Endpoint.Public || (current.Endpoint.Port == service.Endpoint.Port) == releaseFirst {
				t.Fatal("concurrent enable reused a retired binding or lost its retained port", current, err)
			}
		})
	}
}

func TestIntegrationServiceEndpointReleaseRechecksWaitingManager(t *testing.T) {
	d, now, r, applied, service := serviceReleaseProject(t, "http", false)
	setReleaseProjectExposure(t, d, &r, &applied, false)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	manager := addAuthorityMember(t, d, now, r.ActorID, r.TeamID, "release-manager", TeamRoleAdmin)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT id FROM control.teams WHERE id=$1 FOR UPDATE`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	workers.Go(func() {
		_, err := d.ReleaseServiceEndpoint(ctx, service.ID, manager.IdentityID, service.TrustRevision, service.Endpoint.Port, now)
		done <- err
	})
	waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
	if _, err := gate.Exec(ctx, `UPDATE control.team_memberships SET role='member' WHERE id=$1`, manager.ID); err != nil {
		t.Fatal(err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("release used management permission from before its lock wait", err)
	}
	saved, err := d.GetService(ctx, service.ID, r.ActorID)
	if err != nil || saved.Endpoint.Port != service.Endpoint.Port || saved.TrustRevision != service.TrustRevision {
		t.Fatal("denied manager released capacity", saved, err)
	}
}
