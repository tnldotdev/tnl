package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type appliedEndpointFixture struct {
	d         *Database
	now       time.Time
	request   ApplyProjectConfigurationRequest
	applied   AppliedProjectConfiguration
	service   ServiceRecord
	sibling   ServiceRunState
	prepared  ServiceRunPreparation
	run       ServiceRunState
	access    PublisherAccess
	replicas  []enrolledDeploymentReplica
	connector connectorPairFixture
	pair      ConnectorPeerPair
	ingress   IngressLease
	dnsWork   ServiceEndpointDNSWork
}

func appliedEndpointDomain(t *testing.T, d *Database, team, actor, hostname string, now time.Time) Domain {
	t.Helper()
	domain, err := d.ClaimTeamDomain(t.Context(), ClaimDomainRequest{
		TeamID: team, IdentityID: actor, Domain: hostname, IdempotencyKey: hostname,
		RequestDigest: sha256.Sum256([]byte(hostname)),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	work, found, err := d.ClaimDNSAuthorityWork(t.Context(), "apply-endpoint-domain", now, time.Minute)
	if err != nil || !found || work.Reference != domain.DNSAuthorityReference {
		t.Fatal("custom domain did not retain its DNS authority", err)
	}
	work.State, work.ProviderZoneID = "ready", "ZAPPLYENDPOINT"
	work.Nameservers, work.AvailableAt = []string{"ns-1.example.test", "ns-2.example.test"}, now
	if _, err := d.SaveDNSAuthorityWork(t.Context(), work, now); err != nil {
		t.Fatal(err)
	}
	return domain
}

func appliedEndpointAssignment(t *testing.T, assignments DeploymentPublisherAssignments, name string) DeploymentPublisherServiceAssignment {
	t.Helper()
	for _, assignment := range assignments.Services {
		if assignment.Service == name {
			return assignment
		}
	}
	t.Fatal("missing enrolled service assignment", name)
	return DeploymentPublisherServiceAssignment{}
}

func newAppliedEndpointFixture(t *testing.T, protocol string, registered, public bool) appliedEndpointFixture {
	t.Helper()
	d, now, _, leases := newConnectorPairPrerequisites(t)
	session := newOIDCSession(t, d, now)
	member := session.Identity.Memberships[0]
	actor := session.Identity.Identity.ID
	visitor := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: actor, SessionID: session.SessionID})
	domain := appliedEndpointDomain(t, d, member.TeamID, actor, "custom.example.test", now)
	if err := d.ConfigureIngressServicePorts(t.Context(), PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
		t.Fatal(err)
	}
	declaration := ProjectServiceConfiguration{
		Protocol: protocol, Target: "app.internal:3000", Hostname: "api.custom.example.test",
		DomainID: domain.ID, Public: new(public), Access: &ProjectServiceAccess{Team: true},
	}
	if protocol == "http" {
		declaration.HTTP = &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}
	}
	sibling := declaration
	sibling.Hostname, sibling.Public = "sibling.custom.example.test", new(false)
	r := ApplyProjectConfigurationRequest{
		TeamID: member.TeamID, ActorID: actor, ProjectKey: "endpoint-independence", ProjectLabel: "endpoint",
		SourceFingerprint: strings.Repeat("a", 64), DNSAutomation: true, Now: now,
		Configuration: ProjectConfiguration{
			Settings: &DeploymentSettings{DomainID: domain.ID},
			Services: map[string]ProjectServiceConfiguration{"api": declaration, "sibling": sibling},
		},
	}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	scope := DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: actor}
	deployment, err := d.GetDeployment(t.Context(), scope, "production")
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, t.Context(), r.TeamID, r.ProjectKey, "production", actor, 2, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replicas := []enrolledDeploymentReplica{
		enrollAppliedDeployment(t, d, r, enrollment, now),
		enrollAppliedDeployment(t, d, r, enrollment, now),
	}
	access := PublisherAccess{}
	siblingAccess := PublisherAccess{}
	if registered {
		registration, key := managementRegistration(t, scope, now)
		registration.Permissions = map[string][]string{"publish": {"api", "sibling"}}
		registration.AllDeployments, registration.DeploymentIDs = false, []string{deployment.ID}
		credential, err := d.RegisterDeploymentCredential(t.Context(), registration)
		if err != nil {
			t.Fatal(err)
		}
		access = managementAccess(t, d, credential, key, now)
		selected, err := d.GetDeploymentPublication(t.Context(), DeploymentScope{
			TeamID: r.TeamID, ProjectKey: r.ProjectKey, AccessToken: access.Token,
		}, "production", "api", now)
		if err != nil || selected.ID != deployment.Services["api"].ID {
			t.Fatal("registered approval did not select the applied service", err)
		}
		siblingAccess = access
	} else {
		access = deploymentAssignmentAccess(t, d, replicas[0], appliedEndpointAssignment(t, replicas[0].assignments, "api"), now)
		siblingAccess = deploymentAssignmentAccess(t, d, replicas[0], appliedEndpointAssignment(t, replicas[0].assignments, "sibling"), now)
	}
	service, err := d.GetService(t.Context(), deployment.Services["api"].ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	siblingService, err := d.GetService(t.Context(), deployment.Services["sibling"].ID, actor)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := d.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "apply-endpoint", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: 1, HTTPS: true, ServicePorts: []int32{25443},
		ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	prepared, run := readyEndpointDNSServiceRun(t, d, service, leases, access.PublisherIdentity, "original", now)
	if prepared.PublisherGrantID != access.GrantID || prepared.PublisherKeyID != access.KeyID || prepared.PublisherIdentityID != access.ID {
		t.Fatal("run substituted its actual publisher grant, key, or identity")
	}
	_, siblingRun := readyEndpointDNSServiceRun(t, d, siblingService, leases, siblingAccess.PublisherIdentity, "sibling", now)
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	publicKey, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(visitor, actor, publicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	pairRequest := ConnectorPeerPairRequest{
		ServiceID: service.ID, ServiceRunID: run.RunID, RunNumber: run.RunNumber, PublisherIdentityID: access.ID,
		IdempotencyKey: "applied-endpoint", Action: "create", RequestedAt: now,
		Subject: VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: actor, DeviceID: device.ID},
		Source:  DeviceTokenSource{DeviceID: device.ID}, ExpectedRelays: testConnectorPairRelays(run, leases),
	}
	connector := connectorPairFixture{d: d, now: now, visitor: visitor, run: run, request: pairRequest, key: key, leases: leases}
	connector.sign(t, &connector.request)
	pair := connector.create(t)
	f := appliedEndpointFixture{
		d: d, now: now, request: r, applied: applied, service: service, sibling: siblingRun,
		prepared: prepared, run: run, access: access, replicas: replicas, connector: connector,
		pair: pair, ingress: ingress,
	}
	if public {
		work, found, err := d.ClaimServiceEndpointDNSWork(t.Context(), "apply-original-endpoint", now, time.Minute)
		if err != nil || !found || work.ServiceID != service.ID || work.Hostname != service.Endpoint.Hostname {
			t.Fatal("original public DNS was not eligible", err)
		}
		if err := d.ValidateServiceEndpointDNSWork(t.Context(), work, now); err != nil {
			t.Fatal(err)
		}
		f.dnsWork = work
		work.State, work.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
		if _, err := d.SaveServiceEndpointDNSWork(t.Context(), work, now); err != nil {
			t.Fatal(err)
		}
		state, err := d.HeartbeatServiceRun(t.Context(), service.ID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		if err != nil || !state.PublicEndpointReady {
			t.Fatal("original endpoint was not publicly ready", err)
		}
	}
	return f
}

func (f appliedEndpointFixture) nextRequest(t *testing.T) ApplyProjectConfigurationRequest {
	t.Helper()
	current, err := f.d.GetProjectConfiguration(t.Context(), f.request.TeamID, f.request.ProjectKey, f.request.ActorID, "production")
	if err != nil {
		t.Fatal(err)
	}
	r := f.request
	r.ExpectedRevision, r.Configuration = current.Revision, current.Configuration
	r.Now = f.now.Add(time.Second)
	return r
}

func (f appliedEndpointFixture) authority(t *testing.T) []byte {
	t.Helper()
	publishers := []string{f.access.ID, f.replicas[0].member.PublisherIdentityID, f.replicas[1].member.PublisherIdentityID}
	var saved []byte
	err := f.d.pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
	    'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM control.publisher_grants g WHERE publisher_identity_id=ANY($1::text[])),
	    'keys',(SELECT jsonb_agg(to_jsonb(k) ORDER BY k.id) FROM control.publisher_identity_keys k WHERE publisher_identity_id=ANY($1::text[])),
	    'approvals',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.grant_id,a.capability,a.service) FROM control.deployment_management_services a
	        WHERE grant_id IN(SELECT id FROM control.publisher_grants WHERE publisher_identity_id=ANY($1::text[]))),
	    'enrollment',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.enrollment_id,e.service) FROM control.deployment_publisher_enrollment_services e
	        WHERE enrollment_id IN(SELECT enrollment_id FROM control.deployment_publisher_members WHERE publisher_identity_id=ANY($1::text[]))),
	    'visitor',(SELECT jsonb_agg(to_jsonb(v) ORDER BY v.id) FROM control.visitor_grants v WHERE service_id=$2),
	    'runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM control.service_runs r WHERE id=ANY($3::text[])),
	    'slots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.service_run_id,s.connection_slot) FROM control.service_connection_slots s WHERE service_run_id=ANY($3::text[])))`,
		publishers, f.service.ID, []string{f.run.RunID, f.sibling.RunID}).Scan(&saved)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func appliedEndpointWorkerDefinitions(t *testing.T, assignments DeploymentPublisherAssignments) []byte {
	t.Helper()
	data, err := json.Marshal(assignments.Services)
	if err != nil {
		t.Fatal(err)
	}
	var wire []controlv1.DeploymentPublisherServiceAssignment
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, assignment := range assignments.Services {
		if assignment.Configuration.Public != nil || assignment.Configuration.Hostname != "" || assignment.Configuration.DomainID != "" {
			t.Fatal("endpoint desired settings leaked into the worker definition")
		}
	}
	return data
}

func TestIntegrationAppliedServiceEndpointKeepsRegisteredPublication(t *testing.T) {
	f := newAppliedEndpointFixture(t, "http", true, true)
	assertAppliedEndpointMove(t, f, f.service.DomainID, "renamed.custom.example.test")
}

func TestIntegrationAppliedServiceEndpointKeepsEnrolledPublication(t *testing.T) {
	f := newAppliedEndpointFixture(t, "tcp", false, true)
	assertAppliedEndpointMove(t, f, f.service.DomainID, "renamed.custom.example.test")
}

func assertAppliedEndpointMove(t *testing.T, f appliedEndpointFixture, domain, hostname string) {
	t.Helper()
	ctx := t.Context()
	before, pairBefore := f.authority(t), connectorPairSavedAuthority(t, f.d, f.pair.ID)
	definitions := make([][]byte, len(f.replicas))
	for i, replica := range f.replicas {
		definitions[i] = appliedEndpointWorkerDefinitions(t, replica.assignments)
	}
	r := f.nextRequest(t)
	binding := r.Configuration.Services["api"]
	binding.DomainID, binding.Hostname = domain, hostname
	r.Configuration.Services["api"] = binding
	updated, err := f.d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	service, err := f.d.GetService(ctx, f.service.ID, r.ActorID)
	if err != nil || service.ID != f.service.ID || service.TrustRevision != f.service.TrustRevision ||
		!reflect.DeepEqual(service.TLS, f.service.TLS) || service.Protocol != f.service.Protocol ||
		service.EndpointRevision != f.service.EndpointRevision+1 || service.DomainID != domain ||
		service.Endpoint.Hostname != hostname || service.Endpoint.Port != f.service.Endpoint.Port ||
		service.Endpoint.Public != f.service.Endpoint.Public {
		t.Fatal("endpoint edit changed serving identity or lost current endpoint facts", err)
	}
	if updated.Revision != f.applied.Revision+1 || updated.ConfigurationHash == f.applied.ConfigurationHash ||
		updated.Configuration.Services["api"].Hostname != hostname || updated.Configuration.Services["api"].DomainID != domain ||
		!reflect.DeepEqual(updated.Deployments, f.applied.Deployments) {
		t.Fatal("endpoint edit changed namespace authority or skipped desired reconciliation")
	}
	if !bytes.Equal(before, f.authority(t)) || !bytes.Equal(pairBefore, connectorPairSavedAuthority(t, f.d, f.pair.ID)) {
		t.Fatal("endpoint edit changed an actual grant, protocol approval, captured run, slot, or connector")
	}
	for i, replica := range f.replicas {
		assignments, err := f.d.GetDeploymentPublisherAssignments(ctx, replica.lease.AccessToken, r.Now)
		if err != nil || assignments.Revision <= replica.assignments.Revision ||
			assignments.ConfigurationHash == replica.assignments.ConfigurationHash {
			t.Fatal("desired endpoint edit did not advance the assignment envelope", err)
		}
		if !bytes.Equal(definitions[i], appliedEndpointWorkerDefinitions(t, assignments)) {
			t.Fatal("endpoint edit replaced the serialized publication worker definition")
		}
	}
	retry, err := f.d.ApplyProjectConfiguration(ctx, r)
	if err != nil || retry.Revision != updated.Revision || retry.ConfigurationHash != updated.ConfigurationHash {
		t.Fatal("endpoint apply retry was not idempotent", err)
	}
	if !bytes.Equal(before, f.authority(t)) || !bytes.Equal(pairBefore, connectorPairSavedAuthority(t, f.d, f.pair.ID)) {
		t.Fatal("endpoint retry changed preserved publication authority")
	}
	var oldRetired, newPending bool
	if err := f.d.pool.QueryRow(ctx, `SELECT
	    EXISTS(SELECT 1 FROM control.service_endpoints WHERE service_id=$1 AND hostname=$2 AND retired_at IS NOT NULL AND dns_state='removing' AND reusable_after>$4),
	    EXISTS(SELECT 1 FROM control.service_endpoints WHERE service_id=$1 AND hostname=$3 AND domain_id=$5 AND retired_at IS NULL AND public AND dns_state='pending')`,
		service.ID, f.service.Endpoint.Hostname, hostname, r.Now, domain).Scan(&oldRetired, &newPending); err != nil || !oldRetired || !newPending {
		t.Fatal("endpoint reconciliation lost retirement, quarantine, or the validated new DNS binding", err)
	}
	if err := f.d.ValidateServiceEndpointDNSWork(ctx, f.dnsWork, r.Now); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatal("old DNS publication retained provider authority", err)
	}
	stale := f.dnsWork
	stale.State, stale.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	if _, err := f.d.SaveServiceEndpointDNSWork(ctx, stale, r.Now); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatal("old DNS publication committed after endpoint retirement", err)
	}
	f.assertOldRunAndConnector(t, r.Now, service.EndpointRevision)
	f.assertPublicRun(t, r.Now, "", "")
	removal, found, err := f.d.ClaimServiceEndpointDNSWork(ctx, "apply-old-removal", r.Now, time.Minute)
	if err != nil || !found || removal.Hostname != f.service.Endpoint.Hostname || removal.State != ServiceEndpointDNSRemoving {
		t.Fatal("old endpoint DNS removal was not claimable", err)
	}
	removal.State, removal.AvailableAt = ServiceEndpointDNSRemoved, time.Time{}
	if _, err := f.d.SaveServiceEndpointDNSWork(ctx, removal, r.Now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := f.d.ClaimServiceEndpointDNSWork(ctx, "apply-premature-new", r.Now, time.Minute); err != nil || found {
		t.Fatal("new endpoint DNS borrowed the old run's captured certificate identity", err)
	}
	// a different already-enrolled publisher can capture the new endpoint through
	// ordinary run creation. this is not automatic recertification of the old run.
	replica := f.replicas[1]
	assignment := appliedEndpointAssignment(t, replica.assignments, "api")
	access := deploymentAssignmentAccess(t, f.d, replica, assignment, r.Now)
	_, matching := readyEndpointDNSServiceRun(t, f.d, service, f.connector.leases, access.PublisherIdentity, "matching-endpoint", r.Now)
	work, found, err := f.d.ClaimServiceEndpointDNSWork(ctx, "apply-matching-endpoint", r.Now, time.Minute)
	if err != nil || !found || work.ServiceID != service.ID || work.Hostname != hostname || work.DomainID != domain {
		t.Fatal("matching authorized run did not make the current endpoint eligible for DNS", err)
	}
	if err := f.d.ValidateServiceEndpointDNSWork(ctx, work, r.Now); err != nil {
		t.Fatal(err)
	}
	work.State, work.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	if _, err := f.d.SaveServiceEndpointDNSWork(ctx, work, r.Now); err != nil {
		t.Fatal(err)
	}
	f.assertPublicRun(t, r.Now, matching.RunID, hostname)
	f.assertOldRunAndConnector(t, r.Now, service.EndpointRevision)
}

func (f appliedEndpointFixture) assertOldRunAndConnector(t *testing.T, now time.Time, revision int64) {
	t.Helper()
	var captured bool
	if err := f.d.pool.QueryRow(t.Context(), `SELECT certificate_hostname=$2 AND certificate_domain_id=$3
	    AND certificate_scope=$4 AND certificate_identifiers=$5::text[] AND certificate_cache_key=$6
	    FROM control.service_runs WHERE id=$1`, f.run.RunID, f.service.Endpoint.Hostname, f.service.DomainID,
		f.prepared.CertificatePlan.Scope, f.prepared.CertificatePlan.Identifiers, f.prepared.CertificatePlan.CacheKey).Scan(&captured); err != nil || !captured {
		t.Fatal("endpoint move rewrote the retained run's captured certificate plan", err)
	}
	state, err := f.d.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || state.RunID != f.run.RunID || state.RunNumber != f.run.RunNumber || state.State != "ready" ||
		state.EndpointRevision != revision || state.PublicEndpointReady {
		t.Fatal("endpoint move closed the connector run or manufactured public readiness", err)
	}
	if _, err := f.d.HeartbeatServiceRun(t.Context(), f.sibling.ServiceID, f.sibling.RunID, f.sibling.Token, now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("endpoint move closed the sibling run", err)
	}
	selected, err := f.d.SelectServiceRun(f.connector.visitor, f.service.ID, f.request.ActorID, f.connector.request.Subject.DeviceID, now)
	if err != nil || selected.ServiceRunID != f.run.RunID || selected.Endpoint.Hostname != f.service.Endpoint.Hostname {
		t.Fatal("connector selection lost the retained run's captured hostname", err)
	}
	renewal := f.connector.request
	renewal.Action, renewal.PreviousPairID, renewal.PreviousGeneration = "renew", f.pair.ID, f.pair.DeliveryGeneration
	renewal.RequestedAt = now
	f.connector.sign(t, &renewal)
	renewed, err := f.d.RenewConnectorPeerPair(f.connector.visitor, testVisitorIssuer, renewal, now)
	if err != nil || renewed.ID != f.pair.ID || renewed.SessionKey != f.pair.SessionKey || renewed.TrustRevision != f.pair.TrustRevision {
		t.Fatal("endpoint move revoked or replaced the connector session", err)
	}
}

func (f appliedEndpointFixture) assertPublicRun(t *testing.T, now time.Time, run, hostname string) {
	t.Helper()
	snapshot, err := f.d.ReadIngressServices(t.Context(), f.ingress.IngressLeaseIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range snapshot.Runs {
		if entry.ServiceID != f.service.ID {
			continue
		}
		if run == "" || entry.RunID != run || entry.Hostname != hostname || entry.Hostname == f.service.Endpoint.Hostname {
			t.Fatal("current ingress selected retired endpoint or captured run authority")
		}
		found = true
	}
	if found != (run != "") {
		t.Fatal("current ingress did not reflect the matching endpoint/run boundary")
	}
	if f.service.Protocol != "http" {
		admission, err := f.d.AdmitPublicServiceVisitor(t.Context(), f.ingress.IngressLeaseIdentity, PrimaryIngressPoolID,
			mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), f.service.Endpoint.Port, netip.MustParseAddr("192.0.2.10"), now)
		if run == "" {
			if !errors.Is(err, ErrServiceAccess) {
				t.Fatal("retained public port selected the old captured-hostname run", err)
			}
		} else if err != nil || admission.ServiceID != f.service.ID || admission.RunID != run {
			t.Fatal("current public port did not select the ordinary matching run", err)
		}
	}
}
