package state

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationPublicURLAndServiceSharePortInventory(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "url_ports")
	ctx := t.Context()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25444}}); err != nil {
		t.Fatal(err)
	}
	request := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, request, now)
	if url.Port < 25443 || url.Port > 25444 {
		t.Fatal("public URL did not reserve configured capacity", url.Port)
	}
	replayed, err := d.CreatePublicURL(ctx, request, now.Add(time.Second))
	if err != nil || replayed.ID != url.ID || replayed.Port != url.Port {
		t.Fatal("creation replay changed the saved endpoint", replayed, err)
	}
	project := appliedProjectRequest(t, d, now)
	project.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"orders":  {Protocol: "postgres", Target: "localhost:5432", Public: new(true)},
		"private": {Protocol: "http", Target: "localhost:3000"},
	}}
	project = selectedProjectRequest(project, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, project)
	if err != nil || len(applied.Services) != 2 || applied.Services[0].Port == url.Port || applied.Services[0].Port < 25443 || applied.Services[1].Port != 0 {
		t.Fatal("service allocation crossed URL capacity or charged a private binding", applied, err)
	}
	another := request
	another.IdempotencyKey, another.RequestDigest = "another", sha256.Sum256([]byte("another"))
	another.CanonicalHostname = "another." + request.CanonicalHostname
	if _, err := d.CreatePublicURL(ctx, another, now); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("public URL creation bypassed exhausted shared capacity", err)
	}
	var partial int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.public_urls WHERE canonical_hostname=$1`, another.CanonicalHostname).Scan(&partial); err != nil || partial != 0 {
		t.Fatal("failed allocation left a partial URL", partial, err)
	}
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: applied.Services[0].Port, Last: applied.Services[0].Port}}); !errors.Is(err, ErrServicePortsInUse) {
		t.Fatal("inventory shrink forgot a public URL reservation", err)
	}
	if err := d.DeletePublicURL(ctx, request.ActingIdentityID, url.ID, now); err != nil {
		t.Fatal(err)
	}
	if count, err := d.ReleaseServicePorts(ctx, now.Add(6*24*time.Hour)); err != nil || count != 0 {
		t.Fatal("public URL skipped the seven-day quarantine", count, err)
	}
	// elapsed time alone cannot prove that the public DNS binding was removed.
	if _, err := d.pool.Exec(ctx, `UPDATE control.public_urls SET dns_state='removing',dns_available_at=$2 WHERE id=$1`, url.ID, now); err != nil {
		t.Fatal(err)
	}
	if count, err := d.ReleaseServicePorts(ctx, now.Add(8*24*time.Hour)); err != nil || count != 0 {
		t.Fatal("public URL skipped DNS cleanup", count, err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.public_urls SET dns_state='removed',dns_available_at=NULL WHERE id=$1`, url.ID); err != nil {
		t.Fatal(err)
	}
	if count, err := d.ReleaseServicePorts(ctx, now.Add(8*24*time.Hour)); err != nil || count != 1 {
		t.Fatal("settled public URL capacity was not released", count, err)
	}
	replacement, err := d.CreatePublicURL(ctx, another, now.Add(8*24*time.Hour))
	if err != nil || replacement.Port != url.Port || replacement.ID == url.ID {
		t.Fatal("reusable capacity changed or inherited the retired identity", replacement, err)
	}
}

func TestIntegrationPublicURLPortQuarantineTracksLateIssuance(t *testing.T) {
	d, now, runRequest, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	request := oidcRouteRequest(t, d, now)
	publicURL := createTestPublicURL(t, d, request, now)
	runRequest.PublicURLID, runRequest.TeamID = publicURL.ID, request.TeamID
	runRequest.ActingIdentityID, runRequest.MembershipID = request.ActingIdentityID, request.MembershipID
	runRequest.ExpectedMutationRevision = publicURL.MutationRevision
	runRequest.CertificateCacheKey, runRequest.CertificateScope = publicURL.CanonicalHostname, publicURL.CanonicalHostname
	runRequest.CertificateIdentifiers = []string{publicURL.CanonicalHostname}
	setup, err := d.CreatePublishRun(ctx, runRequest, now, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fixture := publishRunFixture{d, now, runRequest, setup, leases}
	issuanceRequest := newTestIssuanceRequest(t, fixture)
	issuance, err := d.CreateCertificateIssuance(ctx, issuanceRequest, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.acme_orders SET finalization_possible=true WHERE id=$1`, issuance.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.DeletePublicURL(ctx, request.ActingIdentityID, publicURL.ID, now); err != nil {
		t.Fatal(err)
	}
	// a deleted record cannot authorize another run or fresh certificate work.
	runRequest.IdempotencyKey = "after-retirement"
	if _, err := d.CreatePublishRun(ctx, runRequest, now.Add(time.Second), time.Minute, time.Minute); !errors.Is(err, ErrPublicURLNotEnabled) {
		t.Fatal("deleted URL authorized another publication", err)
	}
	issuanceRequest.IdempotencyKey = "after-retirement"
	if _, err := d.CreateCertificateIssuance(ctx, issuanceRequest, now); err == nil {
		t.Fatal("retired run authorized another certificate order")
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.public_urls SET dns_state='removed',dns_available_at=NULL WHERE id=$1`, publicURL.ID); err != nil {
		t.Fatal(err)
	}
	assertHeld := func(at time.Time) {
		t.Helper()
		if count, err := d.ReleaseServicePorts(ctx, at); err != nil || count != 0 {
			t.Fatal("unfinished public URL authority became reusable", count, err)
		}
	}
	assertHeld(now.Add(8 * 24 * time.Hour))
	// cancellation is not proof that a finalization never reached the ca.
	var canceled, uncertain bool
	if err := d.pool.QueryRow(ctx, `SELECT state='canceled',finalization_possible FROM control.acme_orders WHERE id=$1`, issuance.ID).Scan(&canceled, &uncertain); err != nil || !canceled || !uncertain {
		t.Fatal("deletion erased uncertain certificate authority", canceled, uncertain, err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.acme_orders SET not_before=$2,not_after=$3 WHERE id=$1`, issuance.ID, now, now.Add(10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertHeld(now.Add(9 * 24 * time.Hour))
	if _, err := d.pool.Exec(ctx, `UPDATE control.publish_runs SET certificate_installed_at=$2,certificate_issuance_id=$3,certificate_not_after=$4 WHERE id=$1`,
		setup.PublishRunID, now, issuance.ID, now.Add(11*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertHeld(now.Add(10 * 24 * time.Hour))
	if _, err := d.pool.Exec(ctx, `INSERT INTO control.acme_authorizations(id,order_id,identifier,authorization_url,challenge_type,challenge_url,challenge_token,challenge_digest,presentation_reference,state,available_at,presented_at,created_at,updated_at)
	    VALUES('url-port-auth',$1,$3,'https://acme.example.test/auth','dns-01','https://acme.example.test/challenge','token',decode(repeat('00',32),'hex'),'url-port-presentation','canceled',$2,$2,$2,$2)`,
		issuance.ID, now, publicURL.CanonicalHostname); err != nil {
		t.Fatal(err)
	}
	assertHeld(now.Add(12 * 24 * time.Hour))
	if _, err := d.pool.Exec(ctx, `UPDATE control.acme_authorizations SET cleanup_completed_at=$1 WHERE id='url-port-auth'`, now.Add(12*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if count, err := d.ReleaseServicePorts(ctx, now.Add(12*24*time.Hour)); err != nil || count != 1 {
		t.Fatal("settled old public URL authority held its port forever", count, err)
	}
}
