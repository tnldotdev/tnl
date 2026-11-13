package deployment

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestSharedOwnerKeepsDeploymentPhasesAndWorkersInTheirIdentity(t *testing.T) {
	m := observability.New("publisher")
	defer m.Shutdown(context.Background())
	ctx, cancel := context.WithCancel(observability.WithMetrics(t.Context(), m))
	defer cancel()
	done := make(chan error, 2)
	identities := make(chan observability.Identity, 2)
	for _, suffix := range []string{"one", "two"} {
		control, private := deploymentFixture(t)
		member := &control.assignment.Member
		member.TeamId, member.DeploymentId, member.PublisherIdentityId = "team-"+suffix, "deployment-"+suffix, "publisher-"+suffix
		control.assignment.Services[0].ServiceId = "service-" + suffix
		identity := observability.Identity{TeamID: member.TeamId, DeploymentID: member.DeploymentId, PublisherIdentityID: member.PublisherIdentityId}
		go func() {
			done <- (Runtime{Control: control, Member: *member, Private: private, PollInterval: time.Millisecond, Publish: func(worker context.Context, _ controlv1.DeploymentPublisherServiceAssignment, health func(bool)) error {
				identities <- observability.IdentityFromContext(worker)
				health(true)
				<-worker.Done()
				return worker.Err()
			}}).Serve(observability.ReplaceIdentity(ctx, identity))
		}()
		select {
		case id := <-identities:
			if id.TeamID != identity.TeamID || id.DeploymentID != identity.DeploymentID || id.PublisherIdentityID != identity.PublisherIdentityID || id.ServiceID != "service-"+suffix {
				t.Fatal("worker crossed deployment scope", id)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("deployment did not start")
		}
		select {
		case <-control.acks:
		case <-time.After(3 * time.Second):
			t.Fatal("deployment did not acknowledge")
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
			if !strings.HasPrefix(operation, "deployment_") {
				continue
			}
			suffix := strings.TrimPrefix(labels["tnl_team_id"], "team-")
			if (suffix != "one" && suffix != "two") || labels["tnl_deployment_id"] != "deployment-"+suffix || labels["tnl_publisher_identity_id"] != "publisher-"+suffix || labels["tnl_service_id"] != "" {
				t.Fatal("deployment phase crossed scope", labels)
			}
			seen[suffix+":"+operation] = true
		}
	}
	for _, suffix := range []string{"one", "two"} {
		for _, operation := range []string{"deployment_lease", "deployment_assignments", "deployment_acknowledge", "deployment_shutdown"} {
			if !seen[suffix+":"+operation] {
				t.Fatalf("missing %s %s", suffix, operation)
			}
		}
	}
}
