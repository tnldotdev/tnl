package state

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationServiceRunNamespaceProvenanceAfterEndpointRelease(t *testing.T) {
	d, now, request, applied, service := serviceReleaseProject(t, "postgres", false)
	ctx := t.Context()
	setReleaseProjectExposure(t, d, &request, &applied, false)
	publisher := serviceReleasePublisher(t, d, request, now)
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "namespace-before-release", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	original, err := controlstatedb.New(d.pool).LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: run.RunID, ServiceID: service.ID})
	if err != nil || original.CertificateNamespace == "" {
		t.Fatal("first run did not capture its actual endpoint namespace", err)
	}
	released, err := d.ReleaseServiceEndpoint(ctx, service.ID, request.ActorID, service.EndpointRevision, service.Endpoint.Port, now)
	if err != nil {
		t.Fatal(err)
	}
	// release currently retains the endpoint row. exercise the existing endpoint
	// retirement operation separately: its receipt still belongs to this exact
	// saved service, hostname and domain, without changing connector authority.
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	if err := retireServiceEndpoints(ctx, tx, service.ID, "", now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{StreamCapacity: 1}); err != nil {
		t.Fatal("endpoint retirement revoked the existing connector run", err)
	}
	if err := d.CloseServiceRun(ctx, run.ServiceID, run.RunID, run.Token, now); err != nil {
		t.Fatal(err)
	}
	next, err := d.PrepareServiceRun(ctx, service.ID, publisher, "namespace-after-retirement", now, ServiceRunRequest{Metadata: released.ServiceMetadata})
	if err != nil {
		t.Fatal("retained exact endpoint provenance did not authorize a new connector-only run", err)
	}
	captured, err := controlstatedb.New(d.pool).LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: next.RunID, ServiceID: service.ID})
	if err != nil || captured.CertificateNamespace != original.CertificateNamespace ||
		captured.CertificateHostname != original.CertificateHostname || captured.CertificateDomainID != original.CertificateDomainID {
		t.Fatal("new run guessed or replaced the retained endpoint provenance", err)
	}
	active, err := d.StartServiceRun(ctx, service.ID, next.RunID, next.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	var retained bool
	if err := d.pool.QueryRow(ctx, `SELECT NOT service.public AND service.service_port=0
		AND endpoint.retired_at IS NOT NULL
		AND NOT EXISTS(SELECT 1 FROM control.service_port_claims claim WHERE claim.service_id=service.id AND claim.state='held')
		FROM control.services service JOIN control.service_endpoints endpoint ON endpoint.service_id=service.id
		AND endpoint.hostname=service.certificate_hostname AND endpoint.domain_id=service.domain_id
		WHERE service.id=$1`, service.ID).Scan(&retained); err != nil || !retained {
		t.Fatal("new connector run resurrected public endpoint authority", err)
	}
	other, err := d.CreateServiceAt(ctx, request.TeamID, request.ActorID, "namespace-other", "namespace-other", ServicePlacement{}, now, ServiceMetadata{Protocol: "postgres"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_endpoints SET service_id=$2 WHERE hostname=$1`, service.Endpoint.Hostname, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, active.ServiceID, active.RunID, active.Token, now, ServiceRunHealth{StreamCapacity: 1}); err != nil {
		t.Fatal("reassignment invalidated the existing run's captured connector authority", err)
	}
	if err := d.CloseServiceRun(ctx, active.ServiceID, active.RunID, active.Token, now); err != nil {
		t.Fatal(err)
	}
	before, err := controlstatedb.New(d.pool).LockService(ctx, service.ID)
	if err != nil {
		t.Fatal(err)
	}
	if denied, err := d.PrepareServiceRun(ctx, service.ID, publisher, "namespace-unprovable", now, ServiceRunRequest{Metadata: released.ServiceMetadata}); err == nil || denied.RunID != "" {
		t.Fatal("unprovable endpoint ownership fell back to a hostname suffix or another service")
	}
	after, err := controlstatedb.New(d.pool).LockService(ctx, service.ID)
	if err != nil || after.NextRunNumber != before.NextRunNumber {
		t.Fatal("failed provenance capture consumed a run number", err)
	}
}
