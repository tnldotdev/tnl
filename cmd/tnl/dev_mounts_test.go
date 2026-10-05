package main

import (
	"context"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func TestDevGroupTargetsWaitForAllServicesBeforePublishing(t *testing.T) {
	targets := newDevGroupTargets(2)
	child := &devProcess{done: make(chan struct{})}
	type result struct {
		name    string
		targets map[string]string
		err     error
	}
	finished := make(chan result, 2)
	go func() {
		values, err := targets.wait(t.Context(), child, "web", "http://127.0.0.1:3000")
		finished <- result{name: "web", targets: values, err: err}
	}()
	select {
	case got := <-finished:
		t.Fatalf("web published before api was ready: %+v", got)
	default:
	}
	go func() {
		values, err := targets.wait(t.Context(), child, "api", "http://127.0.0.1:4000")
		finished <- result{name: "api", targets: values, err: err}
	}()
	for range 2 {
		got := <-finished
		if got.err != nil || got.targets["web"] != "http://127.0.0.1:3000" || got.targets["api"] != "http://127.0.0.1:4000" {
			t.Fatalf("%s targets = %+v, %v", got.name, got.targets, got.err)
		}
	}
}

func TestResolveProjectMountsSelectsDynamicAndConfiguredTargets(t *testing.T) {
	port := 4000
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Services: config.Services{
		"web": {Paths: map[string]config.PathMount{"/api": {Service: "api", StripPrefix: true}}},
		"api": {Dev: &config.Dev{Port: &port}},
	}}}}
	for _, test := range []struct {
		targets map[string]string
		want    string
	}{
		{nil, "http://127.0.0.1:4000"},
		{map[string]string{"api": "http://127.0.0.1:4300"}, "http://127.0.0.1:4300"},
	} {
		mounts, err := resolveProjectMounts(project, "web", test.targets)
		if err != nil || len(mounts) != 1 || mounts[0].Prefix != "/api" || mounts[0].Target != test.want || !mounts[0].StripPrefix {
			t.Fatalf("mounts = %+v, %v", mounts, err)
		}
	}
	project.Config.Services["api"] = config.Service{}
	if _, err := resolveProjectMounts(project, "web", nil); err == nil || !strings.Contains(err.Error(), "run tnl dev without a service") {
		t.Fatalf("missing mounted service target: %v", err)
	}
}

func TestDevGroupTargetsStopWaitingAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	targets := newDevGroupTargets(2)
	child := &devProcess{done: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := targets.wait(ctx, child, "web", "http://127.0.0.1:3000")
		result <- err
	}()
	cause := context.DeadlineExceeded
	cancel(cause)
	if err := <-result; err != cause {
		t.Fatalf("wait after cancellation = %v", err)
	}
}
