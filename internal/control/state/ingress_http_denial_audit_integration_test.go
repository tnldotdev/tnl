package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationIngressHTTPSelectionDenialUsesSignedRoutingAuthority(t *testing.T) {
	f := newPublicServiceHTTPAdmissionFixture(t)
	ctx := t.Context()
	d := f.database
	lease := registerServiceHTTPAdmissionIngress(t, ctx, f, "http-denial")
	snapshot, err := d.ReadIngressServices(ctx, lease.IngressLeaseIdentity, f.now)
	if err != nil || len(snapshot.Runs) != 1 {
		t.Fatal("HTTP audit fixture has no delegated routing", err)
	}
	var before int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.public_service_visitors`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	observation := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: f.service.ID, ServiceKind: "service",
		VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), SourceIP: "192.0.2.30",
		EventType: "connection.open", Outcome: "denied", Reason: "ip_policy", OccurredAt: f.now.Add(time.Second),
		RoutingAuthority: bytes.Clone(snapshot.Runs[0].SourceAuthority)}
	// delayed reporting can follow routing expiry, but the observation still
	// belongs to the delegation's original deadline and exact ingress process.
	reported := snapshot.ValidUntil.Add(time.Second)
	renewReporter := func(current IngressLease) IngressLease {
		t.Helper()
		at := snapshot.ValidUntil.Add(-time.Second)
		if !at.After(current.LeaseExpiresAt) || !at.Before(current.ServingUntil) {
			t.Fatal("fixture did not separate reporter liveness from serving authority")
		}
		renewed, err := d.RenewIngress(ctx, IngressRenewal{IngressLeaseIdentity: current.IngressLeaseIdentity}, at, time.Minute)
		if err != nil || renewed.IngressLeaseIdentity != current.IngressLeaseIdentity ||
			!renewed.LeaseExpiresAt.After(reported) {
			t.Fatal("reporter renewal lost the original ingress identity or delivery lease", err)
		}
		return renewed
	}
	// keep the sender current at delivery without replacing the original
	// routing evidence or increasing its one-minute liveness duration.
	lease = renewReporter(lease)
	result, err := d.IngestIngressServiceObservations(ctx, lease.IngressLeaseIdentity,
		serviceaudit.Batch{Events: []serviceaudit.Observation{observation, observation}}, reported)
	if err != nil || result.Accepted != 1 || result.Duplicates != 1 {
		t.Fatal("signed HTTP selection denial was not deduplicated", result, err)
	}
	page, err := d.ListServiceAudit(ctx, f.project.TeamID, f.project.ActorID, ServiceAuditFilter{ServiceID: f.service.ID}, reported)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range page.Events {
		if event.ID == observation.EventID {
			found = true
			if event.RunID != "" || event.PublisherIdentityID != "" || event.ActorIdentityID != "" || event.DeviceID != "" ||
				event.SourceIP != observation.SourceIP || event.TeamID != f.project.TeamID || event.Reason != "ip_policy" {
				t.Fatal("a selection denial invented serving or visitor authority", event)
			}
		}
	}
	data, err := json.Marshal(page)
	if err != nil || !found || bytes.Contains(data, []byte("routing_authority")) {
		t.Fatal("selection denial was absent or saved routing evidence", err)
	}
	for _, test := range []struct {
		name   string
		change func(*serviceaudit.Observation)
	}{
		{"missing authority", func(o *serviceaudit.Observation) { o.RoutingAuthority = nil; o.Reason = "capacity" }},
		{"malformed authority", func(o *serviceaudit.Observation) { o.RoutingAuthority = []byte("{}") }},
		{"another service", func(o *serviceaudit.Observation) { o.ServiceID = mustOpaqueID(t, opaqueid.ServicePrefix) }},
		{"expired delegation", func(o *serviceaudit.Observation) { o.OccurredAt = snapshot.ValidUntil }},
		{"before delegation", func(o *serviceaudit.Observation) { o.OccurredAt = f.now.Add(-2 * time.Second) }},
		{"signature", func(o *serviceaudit.Observation) {
			a, err := tunnelv1.ReadVisitorSourceAuthority(o.RoutingAuthority)
			if err != nil {
				t.Fatal(err)
			}
			a.MAC[0]++
			o.RoutingAuthority, err = a.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := observation
			invalid.EventID, invalid.RoutingAuthority = serviceaudit.NewID(), bytes.Clone(observation.RoutingAuthority)
			test.change(&invalid)
			if _, err := d.IngestIngressServiceObservations(ctx, lease.IngressLeaseIdentity,
				serviceaudit.Batch{Events: []serviceaudit.Observation{invalid}}, reported); !errors.Is(err, ErrServiceAuditAccess) {
				t.Fatal("HTTP selection denial escaped its signed routing scope", err)
			}
		})
	}
	sibling := registerServiceHTTPAdmissionIngress(t, ctx, f, "http-denial-sibling")
	sibling = renewReporter(sibling)
	if _, err := d.IngestIngressServiceObservations(ctx, sibling.IngressLeaseIdentity,
		serviceaudit.Batch{Events: []serviceaudit.Observation{observation}}, reported); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatal("another ingress adopted the signed delegation", err)
	}
	stale := lease.IngressLeaseIdentity
	stale.IngressLeaseRevision++
	if _, err := d.IngestIngressServiceObservations(ctx, stale,
		serviceaudit.Batch{Events: []serviceaudit.Observation{observation}}, reported); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("a stale ingress reported a selection denial", err)
	}
	if _, err := d.IngestIngressServiceObservations(ctx, lease.IngressLeaseIdentity,
		serviceaudit.Batch{Events: []serviceaudit.Observation{observation}}, lease.LeaseExpiresAt); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("serving authority bypassed the reporter's expired delivery lease", err)
	}
	var after int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.public_service_visitors`).Scan(&after); err != nil || after != before {
		t.Fatal("asynchronous denial reporting created visitor admission records", before, after, err)
	}
}
