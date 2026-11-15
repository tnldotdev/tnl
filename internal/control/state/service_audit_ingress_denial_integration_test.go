package state

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationIngressSelectionDenialAuditRequiresItsAdmissionReceipt(t *testing.T) {
	d, now, request, _, service := serviceReleaseProject(t, "http", false)
	ctx := t.Context()
	publisher := serviceReleasePublisher(t, d, request, now)
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "denial-audit", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, prepared, run, now)
	for _, slot := range run.Connections {
		lease := RelayLeaseIdentity{RelayServiceID: slot.RelayServiceID}
		if err := d.pool.QueryRow(ctx, `SELECT relay_id,relay_run_id,relay_lease_revision
			FROM control.relay_leases WHERE relay_service_id=$1`, slot.RelayServiceID).Scan(&lease.RelayID, &lease.RelayRunID, &lease.RelayLeaseRevision); err != nil {
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
		t.Fatal("audit service is not ready", err)
	}
	ingress, err := d.RegisterIngress(ctx, IngressRegistration{
		IngressID: "selection-denial-audit", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: 1, HTTPS: true, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
	}, now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	if _, err := d.AdmitPublicServiceVisitor(ctx, ingress.IngressLeaseIdentity, PrimaryIngressPoolID, visitor,
		service.Endpoint.Hostname, 443, netip.MustParseAddr("192.0.2.10"), now); err != nil {
		t.Fatal(err)
	}
	if err := d.ClosePublicServiceVisitor(ctx, ingress.IngressLeaseIdentity, visitor, now); err != nil {
		t.Fatal(err)
	}
	observation := serviceaudit.Observation{
		EventID: serviceaudit.NewID(), ServiceID: service.ID, ServiceKind: "service",
		VisitorConnectionID: visitor, SourceIP: "192.0.2.10", EventType: "connection.open",
		Outcome: "denied", Reason: "capacity", OccurredAt: now,
	}
	batch := serviceaudit.Batch{Events: []serviceaudit.Observation{observation, observation}}
	result, err := d.IngestIngressServiceObservations(ctx, ingress.IngressLeaseIdentity, batch, now)
	if err != nil || result.Accepted != 1 || result.Duplicates != 1 {
		t.Fatal("closed selection receipt did not authorize one deduplicated denial", result, err)
	}
	page, err := d.ListServiceAudit(ctx, request.TeamID, request.ActorID, ServiceAuditFilter{ServiceID: service.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range page.Events {
		if event.ID != observation.EventID {
			continue
		}
		found = true
		if event.RunID != "" || event.PublisherIdentityID != "" || event.ActorIdentityID != "" || event.DeviceID != "" ||
			event.ServiceID != service.ID || event.Outcome != "denied" || event.SourceIP != observation.SourceIP {
			t.Fatal("selection denial invented a serving run or authenticated visitor", event)
		}
	}
	if !found {
		t.Fatal("committed selection denial is absent from audit")
	}
	for _, test := range []struct {
		name   string
		change func(*serviceaudit.Observation)
	}{
		{"service", func(o *serviceaudit.Observation) { o.ServiceID = mustOpaqueID(t, opaqueid.ServicePrefix) }},
		{"visitor", func(o *serviceaudit.Observation) {
			o.VisitorConnectionID = mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
		}},
		{"source", func(o *serviceaudit.Observation) { o.SourceIP = "192.0.2.11" }},
		{"before receipt", func(o *serviceaudit.Observation) { o.OccurredAt = now.Add(-2 * time.Second) }},
		{"expired receipt", func(o *serviceaudit.Observation) { o.OccurredAt = now.Add(3 * time.Minute) }},
		{"allowed", func(o *serviceaudit.Observation) { o.Outcome = "allowed" }},
		{"closed", func(o *serviceaudit.Observation) { o.EventType, o.Outcome = "connection.close", "closed" }},
		{"request", func(o *serviceaudit.Observation) { o.EventType = "http.decision" }},
		{"authorization", func(o *serviceaudit.Observation) { o.Reason = "authorization" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := observation
			invalid.EventID = serviceaudit.NewID()
			test.change(&invalid)
			at := now
			if invalid.OccurredAt.After(at) {
				at = invalid.OccurredAt
			}
			if _, err := d.IngestIngressServiceObservations(ctx, ingress.IngressLeaseIdentity, serviceaudit.Batch{Events: []serviceaudit.Observation{invalid}}, at); err == nil {
				t.Fatal("selection denial escaped its exact pending receipt")
			}
		})
	}
	stale := ingress.IngressLeaseIdentity
	stale.IngressLeaseRevision++
	if _, err := d.IngestIngressServiceObservations(ctx, stale, batch, now); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("another ingress lease reported the denial", err)
	}
	other, err := d.RegisterIngress(ctx, IngressRegistration{
		IngressID: "another-selection-denial-audit", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: 1, HTTPS: true, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
	}, now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.IngestIngressServiceObservations(ctx, other.IngressLeaseIdentity, batch, now); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatal("a current sibling ingress lease adopted another process's receipt", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.public_service_visitors SET authorized_at=$2 WHERE visitor_connection_id=$1`, visitor, now); err != nil {
		t.Fatal(err)
	}
	observation.EventID = serviceaudit.NewID()
	if _, err := d.IngestIngressServiceObservations(ctx, ingress.IngressLeaseIdentity, serviceaudit.Batch{Events: []serviceaudit.Observation{observation}}, now); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatal("authorized visitor was reported as an unselected run-less denial", err)
	}
}
