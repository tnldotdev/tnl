package daemon

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationWorkloadTransportPermissionRenewal(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f, issuer := newWorkloadTransportFixture(t, nil)
	for slot := range 2 {
		startSeparatedPrivateIngress(t, f, slot, "quic", nil)
	}
	target := startPrivateEchoTarget(t)
	group, protocol := "private", controlv1.Tcp
	policies := map[string]controlv1.ProjectWorkload{"test": {Provider: controlv1.WorkloadGitHub, Github: &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}}, Services: []string{"private-tcp"}, MaxDurationSeconds: 60}}
	_, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64), Configuration: controlv1.ProjectConfiguration{
		Workloads: &policies, PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {}}, Services: map[string]controlv1.ProjectServiceConfiguration{"private-tcp": {PublisherGroup: &group, Protocol: &protocol, Target: target.address}}, Webhooks: map[string]controlv1.ProjectWebhook{}}})
	if err != nil {
		t.Fatal(err)
	}
	startWorkloadPublishers(t, f, group, "quic")
	job, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
	if err != nil {
		t.Fatal(err)
	}
	session, err := job.Exchange(t.Context(), f.identity.teamID, "workload", strings.Repeat("a", 64), "test", issuer.Sign(t, githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())), []string{"private-tcp"})
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := job.ListServices(t.Context())
	if err != nil || len(inventory.Services) != 1 {
		t.Fatal("native permission service inventory", err)
	}
	control, err := connectorstream.NewWorkloadControl(job)
	if err != nil {
		t.Fatal(err)
	}
	run, err := control.ResolveService(t.Context(), inventory.Services[0].Id)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- connectorstream.Serve(ctx, listener, connectorstream.Config{Control: control, ServiceID: run.ServiceID, Protocol: run.Protocol, TrustRevision: run.TrustRevision, Endpoint: run.Endpoint, ServiceTLS: f.visitorRoots, Ready: func() error { close(ready); return nil }})
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("native permission preparation did not become ready")
	}
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	check := func(message string) {
		t.Helper()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(connection, message); err != nil {
			t.Fatal("renewed native write", err)
		}
		got := make([]byte, len(message))
		if _, err := io.ReadFull(connection, got); err != nil || string(got) != message {
			t.Fatalf("renewed native response %q: %v", got, err)
		}
		_ = connection.SetDeadline(time.Time{})
	}
	check("before-renewal\n")
	// shorten only the disposable parent lease, then renew it normally after
	// both serving owners have prepared the earlier token and parent deadline.
	deadline := time.Now().Add(10 * time.Second)
	if _, err := f.inspect.ExecContext(t.Context(), `UPDATE control.workload_sessions SET lease_expires_at=$2,renewed_at=now()-interval '31 seconds' WHERE id=$1`, session.Id, deadline); err != nil {
		t.Fatal(err)
	}
	waitRuntimeTime(t, deadline.Add(-5*time.Second))
	if _, err := job.Renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitRuntimeTime(t, deadline.Add(time.Second))
	check("after-renewal\n")
}
