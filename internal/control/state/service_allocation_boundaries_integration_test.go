package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationServiceAllocationKeepsDefinitionAndCurrentSigningKey(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	actor := oidcRouteRequest(t, d, now)
	enrollment := publisherEnrollment(t, d, actor, PublisherScope{TeamID: actor.TeamID, Kind: "namespace", DomainID: actor.DomainID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.AllocatePublisherService(ctx, publisher, AllocateServiceRequest{
		Invocation:    mustOpaqueID(t, opaqueid.InvocationPrefix),
		Configuration: ProjectServiceConfiguration{Target: "localhost:3000"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := d.GetServiceForPublisher(ctx, service.ID, publisher, now)
	if err != nil || !reflect.DeepEqual(selected, service) {
		t.Fatal("namespace publication did not select its allocated service", err)
	}
	changed := service.ServiceMetadata
	changed.Protocol = "tcp"
	if _, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, changed, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("management rewrote immutable allocation target intent", err)
	}
	unchanged, err := d.GetServiceForPublisher(ctx, service.ID, publisher, now)
	if err != nil || !reflect.DeepEqual(unchanged, service) {
		t.Fatal("rejected definition edit changed its allocation", err)
	}
	unallocated, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "unallocated", "unallocated", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.services SET certificate_hostname=$2,certificate_scope=$2,domain_id=$3 WHERE id=$1`,
		unallocated.ID, "unallocated."+publisher.Scope.Namespace, publisher.Scope.DomainID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetServiceForPublisher(ctx, unallocated.ID, publisher, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("a matching hostname suffix authorized an unallocated service", err)
	}
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "current-key", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=$1`, publisher.KeyID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetServiceForPublisher(ctx, service.ID, publisher, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("a retired namespace signing key selected a service", err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, ServiceRunHealth{StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("a run token renewed a namespace allocation after its key retired", err)
	}
	if closed, err := d.ExpireServiceRuns(ctx, now); err != nil || closed != 1 {
		t.Fatal("expired namespace authority left its run open", closed, err)
	}
}
