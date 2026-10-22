package group

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestSharedOwnerKeepsGroupPhasesAndWorkersInTheirIdentity(t *testing.T) {
	m := observability.New("publisher")
	defer m.Shutdown(context.Background())
	ctx, cancel := context.WithCancel(observability.WithMetrics(t.Context(), m))
	defer cancel()
	done := make(chan error, 2)
	identities := make(chan observability.Identity, 2)
	for _, suffix := range []string{"one", "two"} {
		control, private := groupFixture(t)
		member := &control.assignment.Member
		member.TeamId, member.GroupId, member.PublisherIdentityId = "team-"+suffix, "group-"+suffix, "publisher-"+suffix
		control.assignment.Services[0].ServiceId = "service-" + suffix
		identity := observability.Identity{TeamID: member.TeamId, PublisherGroupID: member.GroupId, PublisherIdentityID: member.PublisherIdentityId}
		go func() {
			done <- (Runtime{Control: control, Member: *member, Private: private, PollInterval: time.Millisecond, Publish: func(worker context.Context, _ controlv1.PublisherGroupServiceAssignment, health func(bool)) error {
				identities <- observability.IdentityFromContext(worker)
				health(true)
				<-worker.Done()
				return worker.Err()
			}}).Serve(observability.ReplaceIdentity(ctx, identity))
		}()
		select {
		case id := <-identities:
			if id.TeamID != identity.TeamID || id.PublisherGroupID != identity.PublisherGroupID || id.PublisherIdentityID != identity.PublisherIdentityID || id.ServiceID != "service-"+suffix {
				t.Fatal("worker crossed group scope", id)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("group did not start")
		}
		select {
		case <-control.acks:
		case <-time.After(3 * time.Second):
			t.Fatal("group did not acknowledge")
		}
	}
	cancel()
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	families, err := m.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, family := range families {
		if family.GetName() != "tnl_publisher_operation_duration_seconds" {
			continue
		}
		for _, point := range family.Metric {
			labels := map[string]string{}
			for _, label := range point.Label {
				labels[label.GetName()] = label.GetValue()
			}
			operation := labels["tnl_operation"]
			if !strings.HasPrefix(operation, "group_") {
				continue
			}
			suffix := strings.TrimPrefix(labels["tnl_team_id"], "team-")
			if (suffix != "one" && suffix != "two") || labels["tnl_publisher_group_id"] != "group-"+suffix || labels["tnl_publisher_identity_id"] != "publisher-"+suffix || labels["tnl_service_id"] != "" {
				t.Fatal("group phase crossed scope", labels)
			}
			seen[suffix+":"+operation] = true
		}
	}
	for _, suffix := range []string{"one", "two"} {
		for _, operation := range []string{"group_lease", "group_assignments", "group_acknowledge", "group_shutdown"} {
			if !seen[suffix+":"+operation] {
				t.Fatalf("missing %s %s", suffix, operation)
			}
		}
	}
}
