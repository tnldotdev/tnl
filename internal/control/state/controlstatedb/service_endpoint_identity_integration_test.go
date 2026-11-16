package controlstatedb_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/managedcert"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationServiceEndpointEditRetainsCapturedConnectorIdentity(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "endpoint_connector_identity")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	now := time.Now().UTC().Truncate(time.Microsecond)
	owner, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	actor, member := owner.Identity.Identity.ID, owner.Identity.Memberships[0]
	principal, err := d.AuthenticateAccessToken(ctx, owner.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	visitorContext := controlstate.WithControlPrincipal(ctx, principal)
	newID := func(prefix string) string {
		t.Helper()
		id, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	if err := d.EnsurePrimaryIngressPool(ctx, "192.0.2.10", "", now); err != nil {
		t.Fatal(err)
	}
	ingress, err := d.RegisterIngress(ctx, controlstate.IngressRegistration{
		IngressID: "endpoint-ingress", IngressRunID: newID(opaqueid.IngressRunPrefix), ProtocolVersion: 1,
		ConnectionCapacity: 100, IngressPoolID: controlstate.PrimaryIngressPoolID, HTTPS: true,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leases := map[string]controlstate.RelayLease{}
	for _, name := range []string{"endpoint-a", "endpoint-b"} {
		lease, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{
			RelayServiceID: name, RelayID: name, RelayRunID: newID(opaqueid.RelayRunPrefix),
			ProtocolVersion: 1, RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test",
			InternalRelayAddress: name + ".internal:9445", ConnectionCapacity: 100, StreamCapacity: 100,
		}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[name] = lease
	}
	declaration := controlstate.ProjectServiceConfiguration{
		Target: "localhost:3000", Public: new(true),
		HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted"}},
	}
	service, err := d.CreateServiceAt(ctx, member.TeamID, actor, "web", "web", controlstate.ServicePlacement{DNSAutomation: true},
		now, controlstate.ServiceMetadata{PublisherPool: true}, &declaration)
	if err != nil {
		t.Fatal(err)
	}
	// creation spends elapsed authorization time before scheduling endpoint work.
	// observe that actual schedule before testing readiness, not the earlier entry.
	var scheduledAt time.Time
	if err := conn.QueryRow(ctx, `SELECT dns_available_at FROM control.service_endpoints
		WHERE service_id=$1 AND hostname=$2 AND retired_at IS NULL
		AND dns_state='pending' AND public AND dns_automation`, service.ID, service.Endpoint.Hostname).Scan(&scheduledAt); err != nil {
		t.Fatal("read the actual initial endpoint DNS schedule", err)
	}
	if scheduledAt.After(now) {
		now = scheduledAt
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "before-publication", now, time.Minute); err != nil || found {
		t.Fatal("DNS published before the service had a ready certificate and publisher", found, err)
	}
	publish := func(current controlstate.ServiceRecord, key string, at time.Time) (controlstate.PublisherIdentity, controlstate.ServiceRunPreparation, controlstate.ServiceRunState) {
		t.Helper()
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err := d.IssuePublisherEnrollment(ctx, controlstate.CreatePublisherEnrollmentRequest{
			Scope: controlstate.PublisherScope{TeamID: member.TeamID, Kind: "service", ServiceID: current.ID},
			Name:  "endpoint-test", Kind: "installed", EditorID: actor, EditorMembershipID: member.ID,
			PolicyRevision: uint64(member.PolicyRevision), Now: at,
		})
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, at)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := d.PrepareServiceRun(ctx, current.ID, publisher, key, at, controlstate.ServiceRunRequest{Metadata: current.ServiceMetadata})
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.StartServiceRun(ctx, current.ID, prepared.RunID, prepared.RunNumber, publisher, at)
		if err != nil {
			t.Fatal(err)
		}
		for _, slot := range run.Connections {
			lease := leases[slot.RelayServiceID].RelayLeaseIdentity
			if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, current.ID, run.RunID, run.RunNumber,
				slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, at); err != nil {
				t.Fatal(err)
			}
			if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, at); err != nil {
				t.Fatal(err)
			}
		}
		managedcert.Install(t, d, prepared, run, at)
		if ready, err := d.HeartbeatServiceRun(ctx, current.ID, run.RunID, run.Token, at, controlstate.ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || ready.State != "ready" {
			t.Fatal("run is not ready", ready, err)
		}
		return publisher, prepared, run
	}
	publisher, prepared, run := publish(service, "original", now)
	work, found, err := d.ClaimServiceEndpointDNSWork(ctx, "initial", now, time.Minute)
	if err != nil || !found || work.Hostname != prepared.Hostname {
		t.Fatal("initial DNS unavailable", work, found, err)
	}
	work.State, work.AvailableAt = controlstate.ServiceEndpointDNSPublished, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(ctx, work, now); err != nil {
		t.Fatal(err)
	}
	devicePublic, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(visitorContext, actor, devicePublic, now)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := d.SelectServiceRun(visitorContext, service.ID, actor, device.ID, now)
	if err != nil || selection.PairReady == nil {
		t.Fatal("connector selection unavailable", err)
	}
	request := controlstate.ConnectorPeerPairRequest{
		ServiceID: service.ID, ServiceRunID: run.RunID, RunNumber: run.RunNumber, PublisherIdentityID: publisher.ID,
		IdempotencyKey: "connector-owner", Subject: selection.Subject, Source: controlstate.DeviceTokenSource{DeviceID: device.ID},
		Action: "create", RequestedAt: now, ExpectedRelays: selection.PairReady.Relays,
	}
	sign := func() {
		t.Helper()
		proof := tunnelv1.ConnectorPeerPairProof{
			ServiceID: request.ServiceID, ServiceRunID: request.ServiceRunID, RunNumber: request.RunNumber,
			PublisherIdentityID: request.PublisherIdentityID, Subject: request.Subject, IdempotencyKey: request.IdempotencyKey,
			Action: request.Action, RequestedAt: request.RequestedAt, PreviousPairID: request.PreviousPairID, PreviousGeneration: request.PreviousGeneration,
		}
		for i, relay := range request.ExpectedRelays {
			proof.ExpectedRelays[i] = tunnelv1.ConnectorPeerPairRelay{PublisherConnectionID: relay.PublisherConnectionID,
				AssignmentRevision: relay.AssignmentRevision, RelayAddress: relay.RelayAddress, TLSServerName: relay.TLSServerName,
				RelayLease: tunnelv1.ConnectorPeerRelayLease{RelayServiceID: relay.RelayLease.RelayServiceID, RelayID: relay.RelayLease.RelayID,
					RelayRunID: relay.RelayLease.RelayRunID, RelayLeaseRevision: relay.RelayLease.RelayLeaseRevision}}
		}
		message, err := proof.Message()
		if err != nil {
			t.Fatal(err)
		}
		request.Signature = ed25519.Sign(deviceKey, message)
	}
	sign()
	pair, err := d.PrepareConnectorPeerPair(visitorContext, request, now)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://control.example.test"
	if err := d.PrepareVisitorSigningKeys(ctx, issuer, now); err != nil {
		t.Fatal(err)
	}
	declaration.Hostname = "renamed." + member.ManagedLabel + ".example.test"
	changed, err := d.ConfigureService(ctx, service.ID, actor, service.ServiceMetadata, &declaration, controlstate.ServiceUpdateConditions{}, now.Add(time.Second))
	if err != nil || changed.TrustRevision != service.TrustRevision || changed.Endpoint.Hostname == prepared.Hostname {
		t.Fatal("endpoint edit changed target trust or failed to change hostname", changed, err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
	policy, err := d.ReadPublisherVisitorPolicy(ctx, scope, run.RunID, run.RunNumber, run.Token, 0, now.Add(time.Second))
	if err != nil || policy.Policy.Hostname != prepared.Hostname || !policy.Policy.Enabled {
		t.Fatal("endpoint edit replaced the live connector policy identity", policy.Policy, err)
	}
	request.Action, request.PreviousPairID, request.PreviousGeneration, request.RequestedAt = "renew", pair.ID, pair.DeliveryGeneration, now.Add(2*time.Second)
	sign()
	renewed, err := d.RenewConnectorPeerPair(visitorContext, issuer, request, request.RequestedAt)
	if err != nil || renewed.ID != pair.ID || renewed.SessionKey != pair.SessionKey ||
		renewed.Metadata.Endpoint.Hostname != prepared.Hostname || renewed.VisitorPermission.Permission.Hostname != prepared.Hostname {
		t.Fatal("endpoint edit changed the authorized connector owner", err)
	}
	selection, err = d.SelectServiceRun(visitorContext, service.ID, actor, device.ID, now.Add(2*time.Second))
	if err != nil || selection.ServiceRunID != run.RunID || selection.Endpoint.Hostname != prepared.Hostname {
		t.Fatal("connector selection stopped using the selected run's identity", selection, err)
	}
	var issuance string
	var notAfter time.Time
	if err := conn.QueryRow(ctx, `SELECT id,not_after FROM control.acme_orders WHERE service_run_id=$1 AND state='installed'`, run.RunID).Scan(&issuance, &notAfter); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetServiceCertificateIssuance(ctx, service.ID, run.RunID, run.Token, issuance, now.Add(2*time.Second)); err != nil {
		t.Fatal("endpoint edit revoked captured certificate polling", err)
	}
	if err := d.MarkServiceCertificateInstalled(ctx, service.ID, run.RunID, run.Token, issuance, run.RunNumber, notAfter, now.Add(2*time.Second)); err != nil {
		t.Fatal("endpoint edit revoked captured certificate acknowledgement", err)
	}
	_, certificatePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var renewalID string
	for _, test := range []struct {
		hostname string
		allowed  bool
	}{{prepared.Hostname, true}, {changed.Endpoint.Hostname, false}} {
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{test.hostname}}, certificatePrivate)
		if err != nil {
			t.Fatal(err)
		}
		renewal, err := d.CreateServiceCertificateIssuance(ctx, service.ID, run.RunID, run.Token, "https://acme.example.test/directory",
			"renew-"+test.hostname, run.RunNumber, csr, now.Add(2*time.Second))
		if (err == nil) != test.allowed {
			t.Fatal("renewal changed the captured certificate plan", test.hostname, err)
		}
		if test.allowed {
			renewalID = renewal.ID
		}
	}
	routing, err := d.ReadIngressServices(ctx, ingress.IngressLeaseIdentity, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range routing.Runs {
		if entry.ServiceID == service.ID || entry.Hostname == prepared.Hostname || entry.Hostname == changed.Endpoint.Hostname {
			t.Fatal("new public routing used the old run's certificate", entry)
		}
	}
	removal, found, err := d.ClaimServiceEndpointDNSWork(ctx, "retired", now.Add(2*time.Second), time.Minute)
	if err != nil || !found || removal.Hostname != prepared.Hostname || removal.State != controlstate.ServiceEndpointDNSRemoving {
		t.Fatal("endpoint edit did not remove the previous public name", removal, found, err)
	}
	removal.State, removal.AvailableAt = controlstate.ServiceEndpointDNSRemoved, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(ctx, removal, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "replacement", now.Add(2*time.Second), time.Minute); err != nil || found {
		t.Fatal("replacement DNS published without a matching certificate", found, err)
	}
	// a second publisher can now serve the changed endpoint without moving the
	// old connector owner. a DNS claim must lose authority if that run closes.
	if _, err := conn.Exec(ctx, `UPDATE control.acme_orders SET state='canceled' WHERE id=$1`, renewalID); err != nil {
		t.Fatal(err)
	}
	at := now.Add(3 * time.Second)
	_, _, replacement := publish(changed, "replacement", at)
	newDNS, found, err := d.ClaimServiceEndpointDNSWork(ctx, "replacement", at, time.Minute)
	if err != nil || !found || newDNS.Hostname != changed.Endpoint.Hostname {
		t.Fatal("matching run did not enable current endpoint DNS", newDNS, found, err)
	}
	routing, err = d.ReadIngressServices(ctx, ingress.IngressLeaseIdentity, at)
	if err != nil || len(routing.Runs) != 1 || routing.Runs[0].RunID != replacement.RunID ||
		routing.Runs[0].ServiceID != service.ID || routing.Runs[0].Hostname != changed.Endpoint.Hostname {
		t.Fatal("public routing did not select the matching certificate", routing, err)
	}
	if err := d.CloseServiceRun(ctx, service.ID, replacement.RunID, replacement.Token, at); err != nil {
		t.Fatal(err)
	}
	if err := d.ValidateServiceEndpointDNSWork(ctx, newDNS, at); !errors.Is(err, controlstate.ErrServiceEndpointDNSWorkStale) {
		t.Fatal("DNS validation borrowed an old connector run's certificate", err)
	}
}
