package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func endpointReadinessFixture(t *testing.T, exact bool) servicePublicationFixture {
	t.Helper()
	f := publicServingFixture(t, newServicePublicationFixture(t))
	if exact {
		if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
			t.Fatal(err)
		}
		actor := f.actor(t)
		domain := deploymentCustomDomain(t, f.database, ApplyProjectConfigurationRequest{TeamID: f.service.TeamID, ActorID: actor}, f.now)
		var err error
		f.service, err = f.database.ConfigureService(t.Context(), f.service.ID, actor, f.service.ServiceMetadata,
			&ProjectServiceConfiguration{Target: "localhost:3000", DomainID: domain.ID, Hostname: "selected.custom.example.test", Public: new(true)},
			ServiceUpdateConditions{}, f.now)
		if err != nil {
			t.Fatal(err)
		}
		f.start(t, "exact-endpoint", f.now)
	}
	var kind string
	if err := f.database.pool.QueryRow(t.Context(), `SELECT kind FROM control.domains WHERE id=$1`, f.service.DomainID).Scan(&kind); err != nil ||
		exact && kind != "custom" || !exact && kind != "managed" {
		t.Fatal("fixture did not exercise the selected endpoint model", kind, err)
	}
	setEndpointReadinessDNS(t, f, true, ServiceEndpointDNSPending)
	prepareServingPublisher(t, f)
	return f
}

func setEndpointReadinessDNS(t *testing.T, f servicePublicationFixture, automated bool, state ServiceEndpointDNSState) {
	t.Helper()
	result, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_endpoints
	    SET dns_automation=$3,dns_state=$4,
	      dns_available_at=CASE WHEN $4 IN('pending','removing') THEN $5::timestamptz ELSE NULL END
	    WHERE service_id=$1 AND hostname=$2 AND retired_at IS NULL`,
		f.service.ID, f.service.Endpoint.Hostname, automated, string(state), f.now)
	if err != nil || result.RowsAffected() != 1 {
		t.Fatal("fixture did not update one current endpoint", err)
	}
}

func assertEndpointReadinessHeartbeat(t *testing.T, f servicePublicationFixture, want bool) ServiceRunState {
	t.Helper()
	state, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || state.ServiceID != f.service.ID || state.RunID != f.run.RunID || state.RunNumber != f.run.RunNumber ||
		state.State != "ready" || state.EndpointRevision != f.service.EndpointRevision || state.PublicEndpointReady != want {
		t.Fatalf("endpoint readiness changed the run or lost current endpoint facts: state=%+v want endpoint=%t revision=%d error=%v",
			state, want, f.service.EndpointRevision, err)
	}
	return state
}

func TestIntegrationServiceRunEndpointReadinessWaitsForDNS(t *testing.T) {
	for _, exact := range []bool{false, true} {
		t.Run(map[bool]string{false: "managed member", true: "exact hostname"}[exact], func(t *testing.T) {
			f := endpointReadinessFixture(t, exact)
			registerTestIngress(t, f.database, f.now)
			assertEndpointReadinessHeartbeat(t, f, false)
			// run readiness makes DNS work eligible without announcing the
			// public endpoint or introducing another publication lifecycle.
			work, found, err := f.database.ClaimServiceEndpointDNSWork(t.Context(), "endpoint-readiness", f.now, time.Minute)
			if err != nil || !found || work.ServiceID != f.service.ID || work.Hostname != f.service.Endpoint.Hostname {
				t.Fatal("pending endpoint could not publish DNS from its ready run", found, err)
			}
			work.State, work.AvailableAt = ServiceEndpointDNSFailed, time.Time{}
			if _, err := f.database.SaveServiceEndpointDNSWork(t.Context(), work, f.now); err != nil {
				t.Fatal(err)
			}
			assertEndpointReadinessHeartbeat(t, f, false)
			setEndpointReadinessDNS(t, f, true, ServiceEndpointDNSPending)
			work, found, err = f.database.ClaimServiceEndpointDNSWork(t.Context(), "endpoint-readiness-retry", f.now, time.Minute)
			if err != nil || !found {
				t.Fatal("DNS retry lost the existing ready run", found, err)
			}
			work.State, work.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
			if _, err := f.database.SaveServiceEndpointDNSWork(t.Context(), work, f.now); err != nil {
				t.Fatal(err)
			}
			assertEndpointReadinessHeartbeat(t, f, true)
		})
	}
}

func TestIntegrationServiceRunEndpointReadinessRequiresExplicitDNSAndCurrentEndpoint(t *testing.T) {
	f := endpointReadinessFixture(t, false)
	registerTestIngress(t, f.database, f.now)
	for _, test := range []struct {
		name      string
		automated bool
		state     ServiceEndpointDNSState
		ready     bool
	}{
		{"explicit unmanaged", false, ServiceEndpointDNSUnmanaged, true},
		{"automated unmanaged is not publication", true, ServiceEndpointDNSUnmanaged, false},
		{"pending", true, ServiceEndpointDNSPending, false},
		{"failed", true, ServiceEndpointDNSFailed, false},
		{"removing", true, ServiceEndpointDNSRemoving, false},
		{"removed", true, ServiceEndpointDNSRemoved, false},
		{"published", true, ServiceEndpointDNSPublished, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			setEndpointReadinessDNS(t, f, test.automated, test.state)
			assertEndpointReadinessHeartbeat(t, f, test.ready)
		})
	}
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_endpoints SET public=false WHERE service_id=$1`, f.service.ID); err != nil {
		t.Fatal(err)
	}
	assertEndpointReadinessHeartbeat(t, f, false)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_endpoints SET public=true,retired_at=$2,reusable_after=$3 WHERE service_id=$1`,
		f.service.ID, f.now, f.now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertEndpointReadinessHeartbeat(t, f, false)
}

func TestIntegrationServiceRunEndpointReadinessRequiresCompatibleIngress(t *testing.T) {
	f := endpointReadinessFixture(t, false)
	setEndpointReadinessDNS(t, f, true, ServiceEndpointDNSPublished)
	assertEndpointReadinessHeartbeat(t, f, false)
	register := func(name string, https bool, duration time.Duration) IngressLease {
		t.Helper()
		lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
			IngressID: name, IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), ProtocolVersion: 1,
			ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID, HTTPS: https,
		}, f.now, duration)
		if err != nil {
			t.Fatal(err)
		}
		return lease
	}
	incompatible := register("incompatible", false, time.Hour)
	assertEndpointReadinessHeartbeat(t, f, false)
	if _, err := f.database.BeginIngressDrain(t.Context(), incompatible.IngressLeaseIdentity, f.now, f.now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	register("compatible", true, time.Second)
	// the primary externally addressed fallback is usable with compatible
	// ingress; pinning that pool's address does not alter endpoint identity.
	assertEndpointReadinessHeartbeat(t, f, true)
	if err := f.database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", f.now); err != nil {
		t.Fatal(err)
	}
	assertEndpointReadinessHeartbeat(t, f, true)
	incompatible = register("another-incompatible", false, time.Hour)
	assertEndpointReadinessHeartbeat(t, f, false)
	if _, err := f.database.BeginIngressDrain(t.Context(), incompatible.IngressLeaseIdentity, f.now, f.now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertEndpointReadinessHeartbeat(t, f, true)
	f.now = f.now.Add(time.Second)
	assertEndpointReadinessHeartbeat(t, f, false)
}

func TestIntegrationServiceRunEndpointReadinessFencesEndpointAndRunReplacement(t *testing.T) {
	f := endpointReadinessFixture(t, false)
	registerTestIngress(t, f.database, f.now)
	setEndpointReadinessDNS(t, f, true, ServiceEndpointDNSPublished)
	assertEndpointReadinessHeartbeat(t, f, true)
	original, revision := f.run, f.service.EndpointRevision
	var err error
	f.service, err = f.database.ConfigureService(t.Context(), f.service.ID, f.actor(t), f.service.ServiceMetadata,
		&ProjectServiceConfiguration{Target: "localhost:3000", Public: new(true), Hostname: "moved." + f.service.Endpoint.Hostname},
		ServiceUpdateConditions{}, f.now)
	if err != nil || f.service.EndpointRevision != revision+1 {
		t.Fatal("endpoint move did not advance only its endpoint revision", err)
	}
	setEndpointReadinessDNS(t, f, true, ServiceEndpointDNSPublished)
	// even published DNS for the current endpoint cannot make the old run's
	// captured hostname ready. its connector lifetime remains unchanged.
	assertEndpointReadinessHeartbeat(t, f, false)
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, original.RunID, original.Token, f.now); err != nil {
		t.Fatal(err)
	}
	f.start(t, "replacement-endpoint", f.now)
	prepareServingPublisher(t, f)
	current := assertEndpointReadinessHeartbeat(t, f, true)
	if current.RunID == original.RunID || current.RunNumber != original.RunNumber+1 {
		t.Fatal("replacement adopted the original run")
	}
	stale, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, original.RunID, original.Token, f.now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if !errors.Is(err, ErrServiceAccess) || stale.PublicEndpointReady || stale.EndpointRevision != 0 {
		t.Fatal("closed run recovered endpoint readiness", err)
	}
}

func TestIntegrationServiceRunEndpointReadinessPreservesConnectorAuthorityDuringDNSFailure(t *testing.T) {
	f := newConnectorPairFixture(t)
	service, err := f.d.GetService(f.visitor, f.run.ServiceID, f.request.Subject.IdentityID)
	if err != nil {
		t.Fatal(err)
	}
	service, err = f.d.ConfigureService(f.visitor, service.ID, f.request.Subject.IdentityID, service.ServiceMetadata,
		&ProjectServiceConfiguration{Protocol: "tcp", Target: "localhost:3000", Public: new(true)}, ServiceUpdateConditions{}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "connector-dns", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), ProtocolVersion: 1,
		ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID, ServicePorts: []int32{int32(service.Endpoint.Port)},
	}, f.now, time.Minute); err != nil {
		t.Fatal(err)
	}
	pair := f.create(t)
	assertConnector := func(wantEndpoint bool) {
		t.Helper()
		state, err := f.d.HeartbeatServiceRun(t.Context(), service.ID, f.run.RunID, f.run.Token, f.now,
			ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		if err != nil || state.State != "ready" || state.RunID != f.run.RunID || state.RunNumber != f.run.RunNumber ||
			state.EndpointRevision != service.EndpointRevision || state.PublicEndpointReady != wantEndpoint {
			t.Fatal("endpoint state changed the connector run or lost public readiness", state, err)
		}
		selected, err := f.d.SelectServiceRun(f.visitor, service.ID, f.request.Subject.IdentityID, f.request.Subject.DeviceID, f.now)
		if err != nil || selected.ServiceRunID != f.run.RunID {
			t.Fatal("public endpoint state blocked an authorized connector visitor", err)
		}
		retained, err := f.d.PrepareConnectorPeerPair(f.visitor, f.request, f.now)
		if err != nil || retained.ID != pair.ID || retained.SessionKey != pair.SessionKey {
			t.Fatal("public endpoint state replaced or revoked an authorized connector session", err)
		}
	}
	for _, dns := range []ServiceEndpointDNSState{ServiceEndpointDNSPending, ServiceEndpointDNSFailed, ServiceEndpointDNSPublished} {
		setEndpointReadinessDNS(t, servicePublicationFixture{database: f.d, now: f.now, service: service}, true, dns)
		assertConnector(dns == ServiceEndpointDNSPublished)
	}
	service, err = f.d.ConfigureService(f.visitor, service.ID, f.request.Subject.IdentityID, service.ServiceMetadata,
		&ProjectServiceConfiguration{Protocol: "tcp", Target: "localhost:3000", Public: new(false)}, ServiceUpdateConditions{}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	assertConnector(false)
}

func TestIntegrationServiceRunEndpointReadinessCannotReviveExpiredAuthority(t *testing.T) {
	for _, boundary := range []string{"publisher lease", "publisher grant", "certificate"} {
		t.Run(boundary, func(t *testing.T) {
			f := endpointReadinessFixture(t, false)
			registerTestIngress(t, f.database, f.now)
			setEndpointReadinessDNS(t, f, true, ServiceEndpointDNSPublished)
			current := assertEndpointReadinessHeartbeat(t, f, true)
			switch boundary {
			case "publisher lease":
				f.now = current.ExpiresAt
			case "publisher grant":
				if err := f.database.RevokePublisherGrant(t.Context(), f.service.TeamID, f.publisher.ID, f.publisher.GrantID, f.actor(t), f.now); err != nil {
					t.Fatal(err)
				}
			case "certificate":
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET certificate_expires_at=$2 WHERE id=$1`, f.run.RunID, f.now); err != nil {
					t.Fatal(err)
				}
			}
			state, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now,
				ServiceRunHealth{Healthy: true, StreamCapacity: 64})
			if state.PublicEndpointReady {
				t.Fatal("expired authority retained public endpoint readiness", boundary)
			}
			if boundary == "certificate" {
				if err != nil || state.State != "starting" || state.EndpointRevision != f.service.EndpointRevision {
					t.Fatal("certificate expiry lost the existing run or current endpoint facts", err)
				}
			} else if !errors.Is(err, ErrServiceAccess) || state.EndpointRevision != 0 {
				t.Fatal("expired publication authority returned a successful endpoint observation", boundary, err)
			}
		})
	}
}
