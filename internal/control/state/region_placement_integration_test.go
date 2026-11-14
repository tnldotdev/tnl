package state

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/region"
)

func regionalRelays(t *testing.T, d *Database, now time.Time) {
	t.Helper()
	for _, entry := range []struct {
		service string
		region  region.ID
	}{
		{"aws-a", "aws:us-west-1"}, {"aws-b", "aws:us-west-1"},
		{"fly", "fly:sjc"}, {"near", "gcp:us-west2"}, {"far", "aws:us-east-1"},
	} {
		r := relayLifecycleRegistration(entry.service)
		r.Region, r.ConnectionCapacity = entry.region, 1
		if _, err := d.RegisterRelay(t.Context(), r, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIntegrationProviderRegionPlacementAndRecovery(t *testing.T) {
	d, now, request, _ := newPublishRunPrerequisites(t)
	regionalRelays(t, d, now)
	request.PreferredRegions = []string{"FLY:SJC", "aws:us-west-1"}
	setup, err := d.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if setup.PublisherConnections[0].RelayServiceID != "fly" || setup.PublisherConnections[1].RelayServiceID != "aws-a" {
		t.Fatal("provider identity was collapsed or preference order was lost")
	}
	request.PreferredRegions[0] = "fly:sjc"
	retry, err := d.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute)
	if err != nil || !reflect.DeepEqual(setup, retry) {
		t.Fatal("canonical retry changed assignments or credentials", err)
	}
	request.PreferredRegions = []string{"aws:us-west-1", "fly:sjc"}
	if _, err := d.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute); !errors.Is(err, ErrPublishRunIdempotency) {
		t.Fatal("changed preferences reused an idempotency key", err)
	}
	request.PreferredRegions = []string{"sjc"}
	if _, err := d.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute); !errors.Is(err, region.ErrPreference) {
		t.Fatal("generic location was accepted", err)
	}
	// both preferred services are full; the remaining AWS service must precede
	// geographic fallback, then nearby GCP capacity precedes distant or local.
	tx, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	placements, err := selectRelayServicePlacements(t.Context(), controlstatedb.New(tx), now, "fly:sjc", "aws:us-west-1")
	if err != nil || placements[0].relayServiceID != "aws-b" || placements[1].relayServiceID != "near" {
		t.Fatal("capacity or geographic fallback changed", placements, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.relay_leases SET draining=true,drain_deadline=$1 WHERE relay_service_id='fly'`, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	auth := PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: setup.PublicURLID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
	recovered, err := d.HeartbeatPublishRun(t.Context(), auth, now.Add(time.Second), time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.PublisherConnections[0].RelayServiceID != "aws-b" || recovered.PublisherConnections[0].ConnectionAssignmentRevision != 2 || recovered.PublisherConnections[1] != setup.PublisherConnections[1] {
		t.Fatal("recovery lost stored preferences or replaced the surviving assignment")
	}
}

func TestIntegrationProviderRegionRegistrationFence(t *testing.T) {
	d, now := newRelayLifecycleDatabase(t)
	r := relayLifecycleRegistration("regional")
	r.Region = "aws:us-west-1"
	lease, err := d.RegisterRelay(t.Context(), r, now, time.Minute)
	if err != nil || lease.Region != r.Region {
		t.Fatal("registration lost its provider", err)
	}
	r.Region = "fly:sjc"
	if _, err := d.RegisterRelay(t.Context(), r, now, time.Minute); !errors.Is(err, ErrRelayRegistrationConflict) {
		t.Fatal("same service changed providers", err)
	}
	r.RelayID, r.RelayRunID = "another", "another-run"
	if _, err := d.RegisterRelay(t.Context(), r, now, time.Minute); !errors.Is(err, ErrRelayRegistrationConflict) {
		t.Fatal("another process changed the service region", err)
	}
	r.Region = "sjc"
	if _, err := d.RegisterRelay(t.Context(), r, now, time.Minute); !errors.Is(err, region.ErrPreference) {
		t.Fatal("bare city accepted", err)
	}
	i := IngressRegistration{Region: "gcp:us-west1", IngressID: "regional", IngressRunID: "first", ProtocolVersion: 1, ConnectionCapacity: 8, IngressPoolID: PrimaryIngressPoolID}
	il, err := d.RegisterIngress(t.Context(), i, now, time.Minute)
	if err != nil || il.Region != i.Region {
		t.Fatal("ingress lost its provider", err)
	}
	i.Region = "fly:sjc"
	if _, err := d.RegisterIngress(t.Context(), i, now, time.Minute); !errors.Is(err, ErrIngressAlreadyRunning) {
		t.Fatal("live ingress changed regions", err)
	}
}

func TestIntegrationProviderRegionServiceRun(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	regionalRelays(t, d, now)
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"orders": {Protocol: "postgres", Target: "orders.internal:5432"},
	}}
	r = selectedProjectRequest(r, "production")
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	e, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, e, now)
	assignment := replica.assignments.Services[0]
	access := groupAssignmentAccess(t, d, replica, assignment, now)
	metadata := ServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision}
	preferences := []string{"fly:sjc", "aws:us-west-1"}
	prep, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "regional", now, metadata, preferences...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "regional", now, metadata, "aws:us-west-1"); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("preparation retry changed preferences", err)
	}
	run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
	if err != nil || len(run.Connections) != 2 {
		t.Fatal("start regional service", err)
	}
	if run.Connections[0].RelayServiceID != "fly" || run.Connections[1].RelayServiceID != "aws-a" {
		t.Fatal("service start lost prepared preferences")
	}
	// expire only the first never-connected credential and remove that relay.
	// the next heartbeat must retain the second assignment and use stored prefs.
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.service_connection_slots SET credential_expires_at=$2 WHERE publisher_connection_id=$1`, run.Connections[0].PublisherConnectionID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.relay_leases SET draining=true,drain_deadline=$1 WHERE relay_service_id='fly'`, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	recovered, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now.Add(2*time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || len(recovered.Connections) != 2 {
		t.Fatal("service regional recovery", err)
	}
	if recovered.Connections[0].RelayServiceID != "aws-b" || recovered.Connections[0].Revision != 2 || recovered.Connections[1] != run.Connections[1] {
		t.Fatal("service recovery lost preferences or surviving assignment")
	}
}
