package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/certificatetest"
)

func suppliedAliasFixture(t *testing.T) (servicePublicationFixture, string) {
	t.Helper()
	f := newServicePublicationFixture(t)
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	_, parent, _ := strings.Cut(f.service.Endpoint.Hostname, ".")
	var err error
	metadata := f.service.ServiceMetadata
	metadata.PublisherPool = true
	f.service, err = f.database.ConfigureService(t.Context(), f.service.ID, f.actor(t), metadata,
		&ProjectServiceConfiguration{Target: "http://127.0.0.1:3000", Public: new(true), RunAliasParent: parent},
		ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.start(t, "supplied-alias", f.now)
	if f.prepared.RunHostname == "" {
		t.Fatal("supplied fixture omitted the exact run alias")
	}
	return f, parent
}

func TestIntegrationSuppliedCertificateIndependentPublishersAndAuthority(t *testing.T) {
	f, parent := suppliedAliasFixture(t)
	d, ctx := f.database, t.Context()
	issuer := certificatetest.New(t, f.now)
	material := issuer.Issue(t, []string{"*." + parent, "unrelated.example"}, f.now, f.now.Add(30*24*time.Hour), nil)
	install := func(run ServiceRunState, token, chain, previous string, number int64, roots *x509.CertPool) error {
		_, err := d.markSuppliedServiceCertificateInstalled(ctx, run.ServiceID, run.RunID, token, number, chain, previous, f.now, roots)
		return err
	}
	if err := install(f.run, f.run.Token, string(material.Chain), "", f.run.RunNumber, x509.NewCertPool()); !errors.Is(err, ErrCertificateIssuanceInvalid) {
		t.Fatal("untrusted supplied chain was accepted", err)
	}
	wrong := issuer.Issue(t, []string{"other.example"}, f.now, f.now.Add(time.Hour), nil)
	if err := install(f.run, f.run.Token, string(wrong.Chain), "", f.run.RunNumber, issuer.Roots); !errors.Is(err, ErrCertificateIssuanceInvalid) {
		t.Fatal("supplied leaf omitted the approved names", err)
	}
	for _, test := range []struct {
		token  string
		number int64
	}{
		{"another-run-token", f.run.RunNumber}, {f.run.Token, f.run.RunNumber + 1},
	} {
		if err := install(f.run, test.token, string(material.Chain), "", test.number, issuer.Roots); err == nil {
			t.Fatal("supplied install escaped its exact run token or number")
		}
	}
	first, err := d.markSuppliedServiceCertificateInstalled(ctx, f.service.ID, f.run.RunID, f.run.Token, f.run.RunNumber,
		string(material.Chain), "", f.now, issuer.Roots)
	if err != nil || !first.ExpiresAt.Equal(f.now.Add(30*24*time.Hour)) {
		t.Fatal("approved wildcard failed without ACME issuance", err)
	}
	retry, err := d.markSuppliedServiceCertificateInstalled(ctx, f.service.ID, f.run.RunID, f.run.Token, f.run.RunNumber,
		string(material.Chain), "", f.now, issuer.Roots)
	if err != nil || retry != first {
		t.Fatal("same exact supplied install was not idempotent", err)
	}
	// another enrolled identity owns another run and can acknowledge the same
	// website certificate without borrowing the first publisher's issuance.
	enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: f.service.TeamID, ActingIdentityID: f.actor(t)},
		PublisherScope{TeamID: f.service.TeamID, Kind: "service", ServiceID: f.service.ID}, f.now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	sibling := f
	sibling.publisher = publisher
	sibling.start(t, "independent-supplied", f.now)
	if err := install(sibling.run, sibling.run.Token, string(material.Chain), "", sibling.run.RunNumber, issuer.Roots); err != nil {
		t.Fatal("independent publisher could not use shared supplied certificate", err)
	}
	var installed, orders, checkpoints int
	if err := d.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.service_supplied_certificates),
	    (SELECT count(*) FROM control.acme_orders),(SELECT count(*) FROM control.publisher_certificate_checkpoints)`).
		Scan(&installed, &orders, &checkpoints); err != nil || installed != 2 || orders != 0 || checkpoints != 2 {
		t.Fatal("supplied installs created ACME work or lost publisher-scoped checkpoints", installed, orders, checkpoints, err)
	}
	f.readyConnections(t, f.now)
	ready, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || ready.State != "ready" {
		t.Fatal("supplied certificate did not satisfy existing run readiness", ready.State, err)
	}
	if err := d.MarkServiceCertificateInstalled(ctx, f.service.ID, f.run.RunID, f.run.Token, "unrelated-order", f.run.RunNumber, first.ExpiresAt, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("managed install replaced a supplied run", err)
	}
	if err := d.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	if err := install(f.run, f.run.Token, string(material.Chain), "", f.run.RunNumber, issuer.Roots); err == nil {
		t.Fatal("closed run acknowledged a supplied certificate")
	}
}

func TestIntegrationSuppliedCertificateReplacementFencesReplayAndRetainsNames(t *testing.T) {
	f, parent := suppliedAliasFixture(t)
	d, ctx := f.database, t.Context()
	issuer := certificatetest.New(t, f.now)
	first := issuer.Issue(t, []string{"*." + parent}, f.now, f.now.Add(30*24*time.Hour), nil)
	second := issuer.Issue(t, []string{"*." + parent}, f.now, f.now.Add(2*time.Hour), nil)
	install := func(chain []byte, previous string) (string, error) {
		got, err := d.markSuppliedServiceCertificateInstalled(ctx, f.service.ID, f.run.RunID, f.run.Token, f.run.RunNumber, string(chain), previous, f.now, issuer.Roots)
		return got.CertificateSha256, err
	}
	fingerprint, err := install(first.Chain, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := install(second.Chain, ""); !errors.Is(err, ErrCertificateIssuanceInvalid) {
		t.Fatal("replacement skipped its previous-fingerprint fence", err)
	}
	replaced, err := install(second.Chain, fingerprint)
	if err != nil || replaced == fingerprint {
		t.Fatal("supplied replacement failed", err)
	}
	if _, err := install(second.Chain, fingerprint); err != nil {
		t.Fatal("lost replacement reply was not recoverable", err)
	}
	if _, err := install(first.Chain, ""); !errors.Is(err, ErrCertificateIssuanceInvalid) {
		t.Fatal("stale initial ACK restored an old leaf", err)
	}
	if _, err := install(first.Chain, replaced); !errors.Is(err, ErrCertificateIssuanceInvalid) {
		t.Fatal("retired leaf was restored with a fresh fence", err)
	}
	if err := d.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	var reusable time.Time
	if err := d.pool.QueryRow(ctx, `SELECT reusable_after FROM control.service_endpoints WHERE service_run_id=$1`, f.run.RunID).Scan(&reusable); err != nil || reusable.Before(f.now.Add(30*24*time.Hour)) {
		t.Fatal("shorter replacement released a still-certified alias", reusable, err)
	}
	var retained bool
	if err := d.pool.QueryRow(ctx, `SELECT NOT control.service_namespace_reusable($1,$2)`, f.prepared.RunHostname, f.now.Add(8*24*time.Hour)).Scan(&retained); err != nil || !retained {
		t.Fatal("supplied certificate retention did not hold exact-run namespace", err)
	}
}
