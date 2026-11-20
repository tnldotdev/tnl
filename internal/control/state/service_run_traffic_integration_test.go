package state

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestIntegrationServiceRunTrafficStoredRetryAndProjection(t *testing.T) {
	for _, test := range []struct {
		protocol  string
		anonymous bool
	}{{"http", false}, {"http", true}, {"tcp", false}} {
		name := test.protocol
		if test.anonymous {
			name += "-anonymous"
		}
		t.Run(name, func(t *testing.T) {
			protocol := test.protocol
			d, now, project, applied, service := serviceReleaseProject(t, protocol, false)
			ctx := t.Context()
			if test.anonymous {
				binding := project.Configuration.Services["app"]
				binding.HTTP = &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}
				project.Configuration.Services["app"] = binding
				setReleaseProjectExposure(t, d, &project, &applied, true)
			}
			publisher := serviceReleasePublisher(t, d, project, now)
			rate, period, connections, total := 40, "2s", 48, int64(1000)
			request := ServiceRunRequest{
				Metadata: service.ServiceMetadata,
				TrafficSelection: &trafficlimits.Selection{
					Connections: &connections, Rate: &rate, RatePer: &period, TotalConnections: &total,
				},
			}
			prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "traffic", now, request)
			if err != nil {
				t.Fatal(err)
			}
			want := trafficlimits.Default()
			want.Connections, want.Rate, want.RatePer, want.TotalConnections = connections, rate, 2*time.Second, total
			if prepared.Traffic != want {
				t.Fatalf("stored approval: %+v", prepared.Traffic)
			}
			request.TrafficDefaults, request.TrafficCeiling = trafficlimits.Default(), trafficlimits.Ceiling()
			request.TrafficDefaults.UploadBytes = 4 << 20
			request.TrafficDefaults.Connections = 32
			request.TrafficCeiling.Connections = 32
			period = "2000ms"
			retry, err := d.PrepareServiceRun(ctx, service.ID, publisher, "traffic", now.Add(time.Second), request)
			if err != nil || !reflect.DeepEqual(prepared, retry) {
				t.Fatalf("retry re-resolved immutable approval: %+v %v", retry, err)
			}
			changed := request
			changed.TrafficSelection = &trafficlimits.Selection{Connections: new(24)}
			if _, err := d.PrepareServiceRun(ctx, service.ID, publisher, "traffic", now, changed); !errors.Is(err, ErrServiceConflict) {
				t.Fatal("changed selection recovered another approval", err)
			}
			changed.TrafficSelection = &trafficlimits.Selection{Connections: new(0)}
			if _, err := d.PrepareServiceRun(ctx, service.ID, publisher, "traffic", now, changed); !errors.Is(err, ErrTrafficSelection) {
				t.Fatal("retry skipped explicit selection validation", err)
			}
			setReleaseProjectExposure(t, d, &project, &applied, false)
			retry, err = d.PrepareServiceRun(ctx, service.ID, publisher, "traffic", now, request)
			if err != nil || !reflect.DeepEqual(prepared, retry) {
				t.Fatal("endpoint disablement replaced the run approval", retry, err)
			}
			setReleaseProjectExposure(t, d, &project, &applied, true)
			run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
			if err != nil {
				t.Fatal(err)
			}
			installPrivateTestCertificate(t, d, prepared, run, now)
			for _, slot := range run.Connections {
				var lease RelayLeaseIdentity
				lease.RelayServiceID = slot.RelayServiceID
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
			if _, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
				t.Fatal(err)
			}
			registration := IngressRegistration{
				IngressID: "traffic", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
				ProtocolVersion: 1, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
				HTTPS: protocol == "http",
			}
			if protocol != "http" {
				registration.ServicePortRanges = []tcpport.Range{{First: service.Endpoint.Port, Last: service.Endpoint.Port}}
			}
			ingress, err := d.RegisterIngress(ctx, registration, now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
			if protocol == "http" {
				read := func() IngressServiceRun {
					t.Helper()
					entry, err := readIngressServiceRun(ctx, d, ingress.IngressLeaseIdentity, service.ID, run.RunID, now)
					if err != nil || entry.RunNumber != run.RunNumber || entry.Traffic != want || entry.Anonymous != test.anonymous {
						t.Fatal("HTTP routing lost exact stored run approval", entry, err)
					}
					return entry
				}
				first, repeated := read(), read()
				if !first.ValidUntil.Equal(repeated.ValidUntil) {
					t.Fatal("repeated approval projection changed routing observation deadline")
				}
			} else {
				admit := func() PublicServiceVisitorAdmission {
					t.Helper()
					admitted, err := d.AdmitPublicServiceVisitor(ctx, ingress.IngressLeaseIdentity, PrimaryIngressPoolID, visitor, service.Endpoint.Port, netip.MustParseAddr("192.0.2.10"), now)
					if err != nil || admitted.ServiceID != service.ID || admitted.RunID != run.RunID || admitted.RunNumber != run.RunNumber || admitted.Traffic != want {
						t.Fatal("native admission lost exact stored run approval", admitted, err)
					}
					return admitted
				}
				first, repeated := admit(), admit()
				if !first.ExpiresAt.Equal(repeated.ExpiresAt) {
					t.Fatal("approval projection changed admission retry deadline")
				}
			}
			exact := ServiceRunReference{ServiceID: service.ID, RunID: run.RunID, RunNumber: run.RunNumber}
			lookup := func(refs []ServiceRunReference, want []ServiceRunReference) {
				t.Helper()
				closed, err := d.ClosedServiceRuns(ctx, ingress.IngressLeaseIdentity, refs, now)
				if err != nil || !reflect.DeepEqual(closed, want) {
					t.Fatal("closure lookup did not require exact terminal proof", closed, err)
				}
			}
			lookup([]ServiceRunReference{exact}, []ServiceRunReference{})
			setReleaseProjectExposure(t, d, &project, &applied, false)
			lookup([]ServiceRunReference{exact}, []ServiceRunReference{})
			if _, err := d.pool.Exec(ctx, `UPDATE control.service_connection_slots SET state='connected' WHERE service_run_id=$1`, run.RunID); err != nil {
				t.Fatal(err)
			}
			lookup([]ServiceRunReference{exact}, []ServiceRunReference{})
			if protocol != "http" {
				if err := d.ClosePublicServiceVisitor(ctx, ingress.IngressLeaseIdentity, visitor, now); err != nil {
					t.Fatal(err)
				}
			}
			if err := d.CloseServiceRun(ctx, service.ID, run.RunID, run.Token, now); err != nil {
				t.Fatal(err)
			}
			other := exact
			other.ServiceID = mustOpaqueID(t, opaqueid.ServicePrefix)
			wrongNumber := exact
			wrongNumber.RunNumber++
			unknown := exact
			unknown.RunID = mustOpaqueID(t, opaqueid.ServiceRunPrefix)
			lookup([]ServiceRunReference{other, wrongNumber, unknown}, []ServiceRunReference{})
			lookup([]ServiceRunReference{exact, other, wrongNumber, unknown}, []ServiceRunReference{exact})
			stale := ingress.IngressLeaseIdentity
			stale.IngressLeaseRevision++
			if _, err := d.ClosedServiceRuns(ctx, stale, []ServiceRunReference{exact}, now); !errors.Is(err, ErrIngressLeaseStale) {
				t.Fatal("stale ingress received terminal proof", err)
			}
			request.TrafficSelection = nil
			next, err := d.PrepareServiceRun(ctx, service.ID, publisher, "next-traffic", now.Add(time.Second), request)
			if err != nil || next.RunNumber <= run.RunNumber || next.Traffic.Connections != 32 || next.Traffic.UploadBytes != 4<<20 || next.Traffic.TotalConnections != 0 {
				t.Fatal("new run did not resolve new defaults independently", next, err)
			}
			request.TrafficSelection = &trafficlimits.Selection{}
			empty, err := d.PrepareServiceRun(ctx, service.ID, publisher, "next-traffic", now.Add(time.Second), request)
			if err != nil || !reflect.DeepEqual(next, empty) {
				t.Fatal("omitted and empty selections changed retry identity", empty, err)
			}
			lookup([]ServiceRunReference{exact, {ServiceID: next.ServiceID, RunID: next.RunID, RunNumber: next.RunNumber}}, []ServiceRunReference{exact})
		})
	}
}
