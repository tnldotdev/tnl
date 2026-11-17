package state

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func testDirectManagedAdmission(t *testing.T, d *Database, r ApplyProjectConfigurationRequest, applied AppliedProjectConfiguration, run ServiceRunState, now time.Time) {
	t.Helper()
	ctx := t.Context()
	id := func(prefix string) string {
		t.Helper()
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	port := 0
	for _, service := range applied.Services {
		if service.ServiceID == run.ServiceID {
			port = service.Port
		}
	}
	lease, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "managed-direct-ingress", IngressRunID: id(opaqueid.IngressRunPrefix), ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID, ServicePorts: []int32{int32(port)}}, now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	visitor := id(opaqueid.VisitorConnectionPrefix)
	source := netip.MustParseAddr("192.0.2.44")
	admit := func() (PublicServiceVisitorAdmission, error) {
		return d.AdmitPublicServiceVisitor(ctx, lease.IngressLeaseIdentity, PrimaryIngressPoolID, visitor, port, source, now)
	}
	if _, err = admit(); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("private endpoint admitted direct traffic", err)
	}
	setPublic := func(public bool) {
		t.Helper()
		r.DNSAutomation = true
		for name, binding := range r.Configuration.Services {
			binding.Public = new(public)
			r.Configuration.Services[name] = binding
		}
		r.ExpectedRevision = applied.Revision
		applied, err = d.ApplyProjectConfiguration(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
	}
	setPublic(true)
	if _, err := d.pool.Exec(ctx, `UPDATE control.ingress_leases SET service_ports='{}' WHERE ingress_id=$1`, lease.IngressID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "before-exposure", now, time.Minute); err != nil || found {
		t.Fatalf("public DNS preceded an exposed port: found=%t error=%v", found, err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.ingress_leases SET service_ports=ARRAY[$2::int] WHERE ingress_id=$1`, lease.IngressID, port); err != nil {
		t.Fatal(err)
	}
	other, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "managed-direct-not-exposed", IngressRunID: id(opaqueid.IngressRunPrefix), ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID}, now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "partial-pool", now, time.Minute); err != nil || found {
		t.Fatalf("public DNS preceded complete pool exposure: found=%t error=%v", found, err)
	}
	if _, err := d.BeginIngressDrain(ctx, other.IngressLeaseIdentity, now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	publicDNS, found, err := d.ClaimServiceEndpointDNSWork(ctx, "after-exposure", now, time.Minute)
	if err != nil || !found || publicDNS.ServiceID != run.ServiceID || !publicDNS.Public {
		t.Fatalf("ready native service DNS was not claimable: found=%t error=%v", found, err)
	}
	if err := d.ValidateServiceEndpointDNSWork(ctx, publicDNS, now); err != nil {
		t.Fatal(err)
	}
	admitted, err := admit()
	if err != nil || admitted.RunID != run.RunID || len(admitted.Relays) != 2 {
		t.Fatal("direct selection lost the certified run", admitted, err)
	}
	var persisted string
	if err := d.pool.QueryRow(ctx, `SELECT row_to_json(v)::text FROM control.public_service_visitors v WHERE visitor_connection_id=$1`, visitor).Scan(&persisted); err != nil ||
		strings.Contains(persisted, source.String()) || strings.Contains(persisted, "source_ip") ||
		!strings.Contains(persisted, publicVisitorSourceDigest(t, d, run.ServiceID, source.String())) {
		t.Fatal("native admission retained a raw source or lost its binding", err)
	}
	for _, wrong := range []netip.Addr{netip.MustParseAddr("192.0.2.45"), netip.MustParseAddr("2001:db8::1")} {
		status, err := d.PublicServiceVisitorStatus(ctx, lease.IngressLeaseIdentity, visitor, wrong, now)
		if err != nil || status.State != PublicServiceVisitorDenied {
			t.Fatal("status accepted another live source", status, err)
		}
	}
	for _, invalid := range []netip.Addr{{}, netip.MustParseAddr("::"), netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("fe80::1%en0")} {
		if _, err := d.PublicServiceVisitorStatus(ctx, lease.IngressLeaseIdentity, visitor, invalid, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("status accepted an invalid live source", err)
		}
	}
	retry, err := admit()
	if err != nil || retry.ServiceID != admitted.ServiceID || retry.RunID != admitted.RunID || retry.RunNumber != admitted.RunNumber || retry.ConnectionID != admitted.ConnectionID || !retry.ExpiresAt.Equal(admitted.ExpiresAt) || !reflect.DeepEqual(retry.Relays, admitted.Relays) {
		t.Fatal("lost admission response changed its reservation", retry, err)
	}
	if err = d.PromotePublicServiceVisitor(ctx, lease.IngressLeaseIdentity, visitor, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("promoted before visitor authentication", err)
	}
	deviceKey, _, _ := ed25519.GenerateKey(rand.Reader)
	device, err := d.EnrollVisitorDevice(ctx, r.ActorID, deviceKey, now)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	credential, err := d.IssueServiceClientCertificate(ctx, run.ServiceID, r.ActorID, device.ID, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(credential.CertificatePEM))
	authorize := func(ip netip.Addr) (ServiceVisitorValidity, error) {
		return d.AuthorizeServiceClientCertificate(ctx, run.ServiceID, run.RunID, run.Token, visitor, run.RunNumber, ip, port, block.Bytes, now)
	}
	if _, err = authorize(netip.MustParseAddr("192.0.2.45")); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("certificate moved to another source", err)
	}
	decision, err := authorize(source)
	if err != nil || !decision.Allowed || decision.Admitted {
		t.Fatal("TLS authorization bypassed ingress capacity", decision, err)
	}
	status, err := d.PublicServiceVisitorStatus(ctx, lease.IngressLeaseIdentity, visitor, source, now)
	if err != nil || status.State != PublicServiceVisitorAuthenticated {
		t.Fatal("identity was not awaiting promotion", status, err)
	}
	mapped, err := d.PublicServiceVisitorStatus(ctx, lease.IngressLeaseIdentity, visitor, netip.MustParseAddr("::ffff:"+source.String()), now)
	if err != nil || mapped.State != status.State || !mapped.ValidUntil.Equal(status.ValidUntil) {
		t.Fatal("mapped IPv4 changed the original admission binding", mapped, err)
	}
	wrong := lease.IngressLeaseIdentity
	wrong.IngressRunID = id(opaqueid.IngressRunPrefix)
	if err = d.PromotePublicServiceVisitor(ctx, wrong, visitor, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("another ingress promoted the visitor", err)
	}
	for range 2 {
		if err = d.PromotePublicServiceVisitor(ctx, lease.IngressLeaseIdentity, visitor, now); err != nil {
			t.Fatal("promotion did not recover a lost response", err)
		}
	}
	decision, err = authorize(source)
	if err != nil || !decision.Allowed || !decision.Admitted {
		t.Fatal("authenticated visitor remained pending", decision, err)
	}
	if err = d.RevokeVisitorDevice(ctx, r.ActorID, device.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = authorize(source); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("revoked certificate retained access", err)
	}
	status, err = d.PublicServiceVisitorStatus(ctx, lease.IngressLeaseIdentity, visitor, source, now)
	if err != nil || status.State != PublicServiceVisitorDenied {
		t.Fatal("ingress did not observe revocation", status, err)
	}
	setPublic(false)
	if err := d.ValidateServiceEndpointDNSWork(ctx, publicDNS, now); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatalf("public DNS worker survived private transition: %v", err)
	}
	if _, err = admit(); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("stale direct endpoint remained admitted", err)
	}
	if err = d.ClosePublicServiceVisitor(ctx, lease.IngressLeaseIdentity, visitor, now); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationPublicServiceAdmissionRunExclusions(t *testing.T) {
	d, now, service, runs, ingress := publicServiceSelectionFixture(t, 2)
	ctx := t.Context()
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	admit := func(id string, cursor ...ServiceRunCursor) (PublicServiceVisitorAdmission, error) {
		return d.AdmitPublicServiceVisitor(ctx, ingress.IngressLeaseIdentity, PrimaryIngressPoolID, id,
			service.Endpoint.Port, netip.MustParseAddr("192.0.2.30"), now, cursor...)
	}
	first, err := admit(visitor)
	if err != nil || first.RunID != runs[0].RunID || first.RunNumber != runs[0].RunNumber {
		t.Fatal("first selection lost the exact ready run", first, err)
	}
	rejected := ServiceRunReference{ServiceID: service.ID, RunID: first.RunID, RunNumber: first.RunNumber}
	cursor := ServiceRunCursor{Start: rejected, After: rejected}
	if _, err := admit(visitor, cursor); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("changing cursor moved an existing visitor reservation", err)
	}
	retry, err := admit(visitor)
	if err != nil || retry.RunID != first.RunID || !retry.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("denied reselection changed the original reservation", retry, err)
	}
	secondVisitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	second, err := admit(secondVisitor, cursor)
	if err != nil || second.ServiceID != first.ServiceID || second.RunID != runs[1].RunID || second.RunNumber != runs[1].RunNumber {
		t.Fatal("cursor did not select the ready sibling", second, err)
	}
	for _, id := range []string{visitor, secondVisitor} {
		if err := d.ClosePublicServiceVisitor(ctx, ingress.IngressLeaseIdentity, id, now); err != nil {
			t.Fatal(err)
		}
	}
	wrongNumber := rejected
	wrongNumber.RunNumber += 100
	if _, err := admit(mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), ServiceRunCursor{Start: wrongNumber, After: wrongNumber}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("invented run number skipped an exact run", err)
	}
	other := rejected
	other.ServiceID = mustOpaqueID(t, opaqueid.ServicePrefix)
	contradictoryID := rejected
	contradictoryID.RunID = runs[1].RunID
	contradictoryNumber := rejected
	contradictoryNumber.RunNumber++
	last := ServiceRunReference{ServiceID: service.ID, RunID: second.RunID, RunNumber: second.RunNumber}
	for _, cursors := range [][]ServiceRunCursor{
		{{Start: other, After: other}}, {{Start: rejected, After: contradictoryID}}, {{Start: rejected, After: contradictoryNumber}},
		{cursor, cursor}, {{Start: rejected, After: last}},
	} {
		if _, err := admit(mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), cursors...); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("invalid or exhausted cursor admitted a run", cursors, err)
		}
	}
	var pending int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.public_service_visitors WHERE service_id=$1 AND closed_at IS NULL`, service.ID).Scan(&pending); err != nil || pending != 0 {
		t.Fatal("rejected selections retained visitor reservations", pending, err)
	}
}

func publicServiceSelectionFixture(t *testing.T, count int) (*Database, time.Time, ServiceRecord, []ServiceRunState, IngressLease) {
	t.Helper()
	d, now, _, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	request := appliedProjectRequest(t, d, now)
	request.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"web": {Protocol: "tcp", Target: "localhost:3000", Public: new(true)},
	}}
	request = selectedProjectRequest(request, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.GetService(ctx, applied.Services[0].ServiceID, request.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, ctx, request.TeamID, request.ProjectKey, "production", request.ActorID, count, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	runs := make([]ServiceRunState, 0, count)
	for range count {
		replica := enrollAppliedDeployment(t, d, request, enrollment, now)
		access := deploymentAssignmentAccess(t, d, replica, replica.assignments.Services[0], now)
		runs = append(runs, readyAppliedServiceRun(t, d, access, replica.private, service, netip.MustParseAddr("127.0.0.1"), leases, now))
	}
	ingress, err := d.RegisterIngress(ctx, IngressRegistration{
		IngressID: "service-run-exclusions", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: tunnelv1.Version, ServicePorts: []int32{int32(service.Endpoint.Port)}, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return d, now, service, runs, ingress
}

func TestIntegrationPublicServiceAdmissionEligiblePagination(t *testing.T) {
	d, now, service, runs, ingress := publicServiceSelectionFixture(t, 9)
	ctx := t.Context()
	// choose run 5 by current load, then change load while traversing. only
	// the first page uses load; subsequent run-number pages must not repeat.
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET reported_streams=CASE WHEN id=$2 THEN 0 ELSE 1 END WHERE service_id=$1`, service.ID, runs[4].RunID); err != nil {
		t.Fatal(err)
	}
	var continuation []ServiceRunCursor
	for _, index := range []int{4, 5, 6, 7, 8, 0, 1, 2, 3} {
		visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
		admit := func() (PublicServiceVisitorAdmission, error) {
			return d.AdmitPublicServiceVisitor(ctx, ingress.IngressLeaseIdentity, PrimaryIngressPoolID, visitor,
				service.Endpoint.Port, netip.MustParseAddr("192.0.2.30"), now, continuation...)
		}
		selected, err := admit()
		if err != nil || selected.RunID != runs[index].RunID || selected.RunNumber != runs[index].RunNumber {
			t.Fatal("eligible pagination changed its stable circular order", index, selected, err)
		}
		retry, err := admit()
		if err != nil || retry.RunID != selected.RunID || !retry.ExpiresAt.Equal(selected.ExpiresAt) {
			t.Fatal("retry moved or extended an exact native reservation", retry, err)
		}
		if err := d.ClosePublicServiceVisitor(ctx, ingress.IngressLeaseIdentity, visitor, now); err != nil {
			t.Fatal(err)
		}
		ref := ServiceRunReference{ServiceID: selected.ServiceID, RunID: selected.RunID, RunNumber: selected.RunNumber}
		if continuation == nil {
			continuation = []ServiceRunCursor{{Start: ref}}
		}
		continuation[0].After = ref
		if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET reported_streams=0 WHERE service_id=$1`, service.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.AdmitPublicServiceVisitor(ctx, ingress.IngressLeaseIdentity, PrimaryIngressPoolID, mustOpaqueID(t, opaqueid.VisitorConnectionPrefix),
		service.Endpoint.Port, netip.MustParseAddr("192.0.2.30"), now, continuation...); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("exhausted circular pass repeated a run", err)
	}
	var pending int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.public_service_visitors WHERE service_id=$1 AND closed_at IS NULL`, service.ID).Scan(&pending); err != nil || pending != 0 {
		t.Fatal("pagination retained pre-authentication reservations", pending, err)
	}
	for _, mode := range []string{"unhealthy", "capacity", "stale publisher", "all unusable", "denied grants", "earlier grant expiry"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := tx.Rollback(ctx); err != nil {
					t.Error(err)
				}
			}()
			query := `UPDATE control.service_runs SET healthy=false WHERE service_id=$1 AND run_number<$2`
			at := now
			switch mode {
			case "capacity":
				query = `UPDATE control.service_runs SET reported_streams=stream_capacity WHERE service_id=$1 AND run_number<$2`
			case "stale publisher":
				query = `UPDATE control.service_runs SET publisher_expires_at=$3 WHERE service_id=$1 AND run_number<$2`
				at = now.Add(time.Second)
			case "all unusable":
				query = `UPDATE control.service_runs SET healthy=false WHERE service_id=$1 AND run_number<=$2`
			case "denied grants":
				query = `UPDATE control.publisher_grants SET revoked_at=$3 WHERE id IN (SELECT publisher_grant_id FROM control.service_runs WHERE service_id=$1 AND run_number<=$2)`
			}
			if mode == "stale publisher" || mode == "denied grants" {
				_, err = tx.Exec(ctx, query, service.ID, runs[8].RunNumber, at)
			} else {
				_, err = tx.Exec(ctx, query, service.ID, runs[8].RunNumber)
			}
			if err != nil {
				t.Fatal(err)
			}
			expiry := now.Add(time.Second)
			if mode == "earlier grant expiry" {
				_, err = tx.Exec(ctx, `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=(SELECT publisher_grant_id FROM control.service_runs WHERE id=$1)`, runs[8].RunID, expiry)
				if err != nil {
					t.Fatal(err)
				}
			}
			id, number, until, err := selectRoutableServiceRun(ctx, tx, service.ID, service.Endpoint.Hostname, at)
			if mode == "all unusable" || mode == "denied grants" {
				if !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("unusable or denied pool supplied a run", id, err)
				}
			} else if err != nil || id != runs[8].RunID || number != runs[8].RunNumber ||
				mode == "earlier grant expiry" && !until.Equal(expiry) {
				t.Fatal("eligibility or earlier grant expiry was applied after the query limit", id, number, until, err)
			}
		})
	}
}
