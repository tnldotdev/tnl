package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"testing"
)

func TestIntegrationServicePublisherPoolsIndependentDNSCertificates(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, now := f.database, f.now
	meta := f.service.ServiceMetadata
	meta.PublisherPool = true
	updated, err := d.ConfigureService(t.Context(), f.service.ID, f.publisher.CreatorID, meta, nil, ServiceUpdateConditions{}, now)
	if err != nil || !updated.PublisherPool {
		t.Fatal("explicit authorized pool configuration failed", err)
	}
	f.service = updated
	installPrivateTestCertificate(t, d, f.prepared, f.run, now)
	f.readyConnections(t, now)
	if _, err := d.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}

	e := publisherEnrollment(t, d, serviceTestAuthority{TeamID: f.service.TeamID, ActingIdentityID: f.publisher.CreatorID}, PublisherScope{TeamID: f.service.TeamID, Kind: "service", ServiceID: f.service.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher2, err := d.RedeemPublisherEnrollment(t.Context(), e.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared2, err := d.PrepareServiceRun(t.Context(), f.service.ID, publisher2, "publisher-2", now, ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	run2, err := d.StartServiceRun(t.Context(), f.service.ID, prepared2.RunID, prepared2.RunNumber, publisher2, now)
	if err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, prepared2, run2, now)
	for _, slot := range run2.Connections {
		lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, f.service.ID, run2.RunID, run2.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run2.RunID, run2.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), f.service.ID, run2.RunID, run2.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}

	_ = registerTestIngress(t, d, now)
	var issuance1, issuance2 string
	if err = d.pool.QueryRow(t.Context(), `SELECT certificate_issuance_id FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&issuance1); err != nil {
		t.Fatal(err)
	}
	if err = d.pool.QueryRow(t.Context(), `SELECT certificate_issuance_id FROM control.service_runs WHERE id=$1`, run2.RunID).Scan(&issuance2); err != nil {
		t.Fatal(err)
	}
	if issuance1 == "" || issuance1 == issuance2 {
		t.Fatal("pool publishers shared a certificate issuance")
	}
	var readyCount int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_runs WHERE service_id=$1 AND state='ready'`, f.service.ID).Scan(&readyCount); err != nil || readyCount != 2 {
		t.Fatalf("two ready certificate holders: ready=%d err=%v", readyCount, err)
	}
	if err = d.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now); err != nil {
		t.Fatal(err)
	}
	var run1State, run2State string
	if err = d.pool.QueryRow(t.Context(), `SELECT state FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&run1State); err != nil || run1State != "closed" {
		t.Fatalf("closed run state=%q err=%v", run1State, err)
	}
	if err = d.pool.QueryRow(t.Context(), `SELECT state FROM control.service_runs WHERE id=$1`, run2.RunID).Scan(&run2State); err != nil || run2State != "ready" {
		t.Fatalf("run tombstone removed pool sibling: state=%q err=%v", run2State, err)
	}
	if err = d.RevokePublisherGrant(t.Context(), f.service.TeamID, publisher2.ID, publisher2.GrantID, f.publisher.CreatorID, now); err != nil {
		t.Fatal(err)
	}
	if err = d.pool.QueryRow(t.Context(), `SELECT state FROM control.service_runs WHERE id=$1`, run2.RunID).Scan(&run2State); err != nil || run2State == "ready" {
		t.Fatalf("revoked pool run retained ready state: state=%q err=%v", run2State, err)
	}
}

func TestIntegrationServicePoolBrowserHandoffSurvivesSiblingClosure(t *testing.T) {
	f := newServiceHTTPFixture(t)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.services SET publisher_pool=true WHERE id=$1`, f.service.ID); err != nil {
		t.Fatal(err)
	}
	f.service.PublisherPool = true
	f.run = f.publish(t, f.service)
	sibling := f
	sibling.run = f.publish(t, f.service)
	handoff, _ := f.browser(t, "", f.project.ActorID)
	cookie, err := f.database.RedeemServiceBrowserHandoff(t.Context(), sibling.auth(), handoff.Token, f.now)
	if err != nil {
		t.Fatalf("pool sibling could not redeem host-bound browser handoff: %v", err)
	}
	var first, second string
	if err := f.database.pool.QueryRow(t.Context(), `SELECT a.certificate_issuance_id,b.certificate_issuance_id
		FROM control.service_runs a CROSS JOIN control.service_runs b WHERE a.id=$1 AND b.id=$2`,
		f.run.RunID, sibling.run.RunID).Scan(&first, &second); err != nil || first == second {
		t.Fatal("service pool publishers shared a certificate issuance", err)
	}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	if permission, err := f.database.ServiceBrowserSession(t.Context(), sibling.auth(), cookie.CookieSecret, false, f.now); err != nil || !permission.VisitAllowed {
		t.Fatalf("closed pool sibling invalidated browser access: %+v %v", permission, err)
	}
	if _, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, sibling.auth().Subject, BrowserSessionTokenSource{Secret: cookie.CookieSecret}, f.now); err != nil {
		t.Fatal("closed pool sibling invalidated captured browser permission", err)
	}
}
