package state

import (
	"bytes"
	"testing"
	"time"
)

func TestIntegrationDomainReleaseRestoredIssuedCertificateAndCleanupFences(t *testing.T) {
	for _, certificateState := range []string{"waiting_for_install", "installed", "canceled"} {
		t.Run(certificateState, func(t *testing.T) {
			owner, member, domain, fixtures := sessionLockAuthorityFixtures(t)
			f := fixtures[0]
			d, now, ctx := f.database, f.now, t.Context()
			if err := d.EnsurePrimaryIngressPool(ctx, "192.0.2.10", "", now); err != nil {
				t.Fatal(err)
			}
			configuration, _, err := d.GetServiceConfiguration(ctx, f.service.ID, member.IdentityID)
			if err != nil || configuration == nil {
				t.Fatal("custom-domain fixture has no real service declaration", err)
			}
			configuration.Public = new(true)
			f.service, err = d.ConfigureService(ctx, f.service.ID, member.IdentityID, f.service.ServiceMetadata,
				configuration, ServiceUpdateConditions{}, now)
			if err != nil {
				t.Fatal(err)
			}
			setEndpointReadinessDNS(t, f, true, ServiceEndpointDNSPending)
			f.run, err = d.StartServiceRun(ctx, f.service.ID, f.prepared.RunID, f.prepared.RunNumber, f.publisher, now)
			if err != nil {
				t.Fatal(err)
			}
			work := createPlanIssuanceWork(t, d, now, f.run, f.prepared.CertificatePlan, true, nil)
			if certificateState == "installed" {
				if err := d.MarkServiceCertificateInstalled(ctx, f.service.ID, f.run.RunID, f.run.Token,
					work.ID, f.run.RunNumber, *work.NotAfter, now); err != nil {
					t.Fatal(err)
				}
			}
			if err := d.ReleaseTeamDomain(ctx, owner, member.TeamID, domain.ID, now); err != nil {
				t.Fatal(err)
			}
			for _, fixture := range fixtures {
				if err := d.DeleteService(ctx, fixture.service.ID, owner, now); err != nil {
					t.Fatal("domain release prevented saved-service cleanup", err)
				}
			}
			var state string
			var notAfter time.Time
			var certificate []byte
			if err := d.pool.QueryRow(ctx, `SELECT state,not_after,certificate_pem FROM control.acme_orders WHERE id=$1`,
				work.ID).Scan(&state, &notAfter, &certificate); err != nil {
				t.Fatal(err)
			}
			wantState := "waiting_for_install"
			if certificateState == "installed" {
				wantState = "installed"
			}
			if state != wantState || !notAfter.Equal(*work.NotAfter) || !bytes.Equal(certificate, work.CertificatePEM) || len(certificate) == 0 {
				t.Fatal("closure/deletion lost issued certificate state, PEM, or exact expiry", state, notAfter)
			}
			if certificateState == "canceled" {
				if _, err := d.pool.Exec(ctx, `UPDATE control.acme_orders SET state='canceled' WHERE id=$1`, work.ID); err != nil {
					t.Fatal(err)
				}
				wantState = "canceled"
			}
			assertRelease := func(at time.Time, want bool) {
				t.Helper()
				ready, err := d.DNSAuthorityReleaseReady(ctx, domain.ID, at)
				if err != nil || ready != want {
					t.Fatalf("domain release at %s ready=%t want=%t: %v", at, ready, want, err)
				}
			}
			assertRelease(notAfter, false)
			dnsWork, found, err := d.ClaimServiceEndpointDNSWork(ctx, "restored-domain-cleanup", now, time.Minute)
			if err != nil || !found || dnsWork.ServiceID != f.service.ID || dnsWork.State != ServiceEndpointDNSRemoving {
				t.Fatal("released service did not retain its real pending DNS removal", dnsWork, found, err)
			}
			dnsWork.State, dnsWork.AvailableAt = ServiceEndpointDNSRemoved, time.Time{}
			if _, err := d.SaveServiceEndpointDNSWork(ctx, dnsWork, now); err != nil {
				t.Fatal(err)
			}
			for _, at := range []time.Time{now, notAfter.Add(-time.Microsecond), notAfter, notAfter.Add(time.Second)} {
				assertRelease(at, !at.Before(notAfter))
			}
			// canceled authorization state does not erase an unfinished DNS
			// presentation cleanup.
			result, err := d.pool.Exec(ctx, `UPDATE control.acme_authorizations
				SET state='canceled',cleanup_completed_at=NULL WHERE order_id=$1`, work.ID)
			if err != nil || result.RowsAffected() == 0 {
				t.Fatal("issued certificate fixture has no authorization cleanup history", err)
			}
			assertRelease(notAfter, false)
			if _, err := d.pool.Exec(ctx, `UPDATE control.acme_authorizations
				SET state='complete',cleanup_completed_at=$2 WHERE order_id=$1`, work.ID, notAfter); err != nil {
				t.Fatal(err)
			}
			assertRelease(notAfter, true)
			authority, found, err := d.ClaimDNSAuthorityWork(ctx, "restored-domain-release", notAfter, time.Minute)
			if err != nil || !found || authority.Reference != domain.DNSAuthorityReference {
				t.Fatal("settled domain release was not claimable", found, err)
			}
			authority.State, authority.AvailableAt = DNSAuthorityReleased, notAfter
			if _, err := d.SaveDNSAuthorityWork(ctx, authority, notAfter); err != nil {
				t.Fatal(err)
			}
			var released bool
			if err := d.pool.QueryRow(ctx, `SELECT state='released' AND released_at IS NOT NULL
				FROM control.domains WHERE id=$1`, domain.ID).Scan(&released); err != nil || !released {
				t.Fatal("fully settled authority did not release its actual domain", err)
			}
			if err := d.pool.QueryRow(ctx, `SELECT state,not_after,certificate_pem FROM control.acme_orders WHERE id=$1`,
				work.ID).Scan(&state, &notAfter, &certificate); err != nil ||
				state != wantState || !notAfter.Equal(*work.NotAfter) || !bytes.Equal(certificate, work.CertificatePEM) {
				t.Fatal("domain release discarded retained certificate evidence", err)
			}
		})
	}
	t.Run("independent-finalization-history", func(t *testing.T) {
		owner, member, domain, fixtures := sessionLockAuthorityFixtures(t)
		f := fixtures[0]
		d, now, ctx := f.database, f.now, t.Context()
		var err error
		f.run, err = d.StartServiceRun(ctx, f.service.ID, f.prepared.RunID, f.prepared.RunNumber, f.publisher, now)
		if err != nil {
			t.Fatal(err)
		}
		// persist the real ca response before the terminal receipt, never rewind
		// an installed order or alter its installation history.
		work := createPlanIssuanceWork(t, d, now, f.run, f.prepared.CertificatePlan, true, func(work *ACMEOrderWork) {
			work.State = ACMEOrderFinalizing
		})
		if work.State != ACMEOrderFinalizing || !work.FinalizationPossible || work.NotAfter == nil || len(work.CertificatePEM) == 0 {
			t.Fatal("fixture did not retain an actual issued leaf awaiting its final receipt")
		}
		if err := d.ReleaseTeamDomain(ctx, owner, member.TeamID, domain.ID, now); err != nil {
			t.Fatal(err)
		}
		for _, fixture := range fixtures {
			if err := d.DeleteService(ctx, fixture.service.ID, owner, now); err != nil {
				t.Fatal("domain release prevented saved-service cleanup", err)
			}
		}
		at := *work.NotAfter
		ready, err := d.DNSAuthorityReleaseReady(ctx, domain.ID, at)
		if err != nil || ready {
			t.Fatal("past leaf deadline settled unfinished finalization", ready, err)
		}
		current, found, err := d.ClaimACMEOrderWork(ctx, "restored-finalization-receipt", at, time.Minute)
		if err != nil || !found || current.ID != work.ID || current.State != ACMEOrderFinalizing ||
			current.WorkEpoch <= work.WorkEpoch || !current.WorkExpiresAt.After(at) {
			t.Fatal("claim current finalization work without reviving publisher authority", found, err)
		}
		current.State, current.AvailableAt = ACMEOrderWaitingForInstall, at
		completed, err := d.SaveACMEOrderWork(ctx, current, at)
		if err != nil || completed.State != ACMEOrderWaitingForInstall || completed.NotAfter == nil ||
			!completed.NotAfter.Equal(at) || !bytes.Equal(completed.CertificatePEM, work.CertificatePEM) {
			t.Fatal("final receipt changed the retained certificate or expiry", err)
		}
		ready, err = d.DNSAuthorityReleaseReady(ctx, domain.ID, at)
		if err != nil || !ready {
			t.Fatal("completed finalization receipt did not settle release at the same deadline", ready, err)
		}
		var neverInstalled bool
		if err := d.pool.QueryRow(ctx, `SELECT installed_at IS NULL FROM control.acme_orders WHERE id=$1`, work.ID).Scan(&neverInstalled); err != nil || !neverInstalled {
			t.Fatal("finalization fixture changed installation history", err)
		}
	})
}
