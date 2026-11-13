package installed

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
)

func TestStandaloneDeploymentsIsolateBlockedStoppedAndHealthyWorkers(t *testing.T) {
	options := testOptions(t)
	options.StandaloneDeployments = true
	r, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	a, _, ka := kindFixture(t, KindDeployment)
	b, _, kb := kindFixture(t, KindDeployment)
	a.ID = JobKey(a.Server, "deployment", a.DeploymentMember.DeploymentId+":"+a.DeploymentInstance)
	b.ID = JobKey(b.Server, "deployment", b.DeploymentMember.DeploymentId+":"+b.DeploymentInstance)
	b.DeploymentMember.TeamId = "other-team"
	b.Name = a.Name
	if err := r.ReplaceDeployments(t.Context(), []DeploymentInstall{{a, ka}, {b, kb}}); err != nil {
		t.Fatal(err)
	}
	duplicate := a
	duplicate.DeploymentInstance = "different-instance"
	duplicate.ID = JobKey(a.Server, "deployment", a.DeploymentMember.DeploymentId+":"+duplicate.DeploymentInstance)
	if err := r.InstallDeployment(t.Context(), duplicate, *a.DeploymentMember, ka); !errors.Is(err, ErrJobExists) {
		t.Fatal("same publisher accepted under another instance", err)
	}
	var healthyStarts, healthyJoins atomic.Int32
	engine := Engine{Registry: r, PollInterval: time.Millisecond, RetryMin: time.Millisecond, RetryMax: 2 * time.Millisecond, Deployment: func(ctx context.Context, job Job, _ *clienttelemetry.Collector, observe func(int64, bool) error) error {
		if job.ID == a.ID {
			return clientcontrol.ErrUnauthenticated
		}
		healthyStarts.Add(1)
		defer healthyJoins.Add(1)
		if err := observe(1, true); err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	}}
	cancel, done := startEngine(t, engine)
	await(t, func() bool {
		jobs, _ := r.List(t.Context())
		return len(jobs) == 2 && (jobs[0].Status.State == "blocked" && jobs[1].Status.State == "ready" || jobs[1].Status.State == "blocked" && jobs[0].Status.State == "ready")
	})
	if err := r.Stop(t.Context(), a.ID); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool {
		jobs, _ := r.List(t.Context())
		for _, j := range jobs {
			if j.ID == a.ID {
				return j.Status.State == "stopped"
			}
		}
		return false
	})
	if err := r.Start(t.Context(), a.ID); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool {
		jobs, _ := r.List(t.Context())
		for _, j := range jobs {
			if j.ID == a.ID {
				return j.Status.State == "blocked"
			}
		}
		return false
	})
	if healthyStarts.Load() != 1 || healthyJoins.Load() != 0 {
		t.Fatal("A restarted B")
	}
	joinEngine(t, cancel, done)
	if healthyJoins.Load() != 1 {
		t.Fatal("shutdown did not join B")
	}
}
