package app

import (
	"slices"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestProjectObservationPreservesInvocationsWithoutResurrectingRemovedDeclarations(t *testing.T) {
	invocation := "ivk_" + strings.Repeat("A", 22)
	project := clientproject.Project{Config: config.TNL{Services: config.Services{"web": {}, "remote": {PublisherGroup: new("production")}}}}
	saved := Snapshot{Cursor: "native-cursor", Services: []Service{
		{Name: "removed", Registered: true},
		{Name: "remote", Registered: true},
		{Name: "web", Registered: true, Ready: true, Readiness: Readiness{Path: "/old"}, Observation: &Observation{Ready: true}},
		{Name: invocation, Registered: true, Routable: true, Ready: true, RegistrationID: "reg_current", PublicURL: "https://app.example", Target: "http://127.0.0.1:3000", Readiness: Readiness{Path: "/health"}},
	}}
	got := projectObservationSnapshot(project, saved)
	if got.Cursor != saved.Cursor || len(got.Services) != 2 || got.Services[0].Name != "web" || got.Services[0].Ready || got.Services[0].Observation != nil || got.Services[0].Readiness.Path != "/" || got.Services[1] != saved.Services[3] {
		t.Fatalf("project observation lost current definitions or an independent invocation: %+v", got)
	}
	if !saved.Services[2].Ready || saved.Services[2].Readiness.Path != "/old" {
		t.Fatal("observation mutated its input")
	}
	project.Config.Services = nil
	got = projectObservationSnapshot(project, saved)
	if len(got.Services) != 1 || got.Services[0].Name != invocation {
		t.Fatal("standalone observation required a project declaration")
	}
}

func TestProjectObservationStaleInvocationUsesItsTunnelIDNotAConfiguredServiceName(t *testing.T) {
	invocation := "ivk_" + strings.Repeat("A", 22)
	saved := Snapshot{Services: []Service{{Name: invocation, Registered: true, Routable: true, Ready: true, TunnelID: "tunnel", Target: "http://127.0.0.1:3000", Observation: &Observation{Ready: true}}}, Publications: []clientstate.TunnelInfo{{ID: "tunnel", Target: "http://127.0.0.1:3000", State: clientstate.TunnelStateStale}}}
	got := projectObservationSnapshot(clientproject.Project{}, saved)
	service := got.Services[0]
	if service.Registered || service.Routable || service.Ready || service.Observation != nil || service.Failure != "runtime.manager_unavailable" {
		t.Fatal("stale invocation tunnel retained readiness")
	}
}

func TestLocalObservationSelectionUsesCurrentInvocationsAndExactExplicitKeys(t *testing.T) {
	current, stopped := "ivk_"+strings.Repeat("A", 22), "ivk_"+strings.Repeat("B", 22)
	project := clientproject.Project{Config: config.TNL{Services: config.Services{"web": {}, "remote": {PublisherGroup: new("production")}}}}
	snapshot := Snapshot{Services: []Service{{Name: current, RegistrationID: "reg_current"}, {Name: stopped}, {Name: "removed", RegistrationID: "reg_old"}}}
	names, err := LocalObservationServices(project, snapshot, nil)
	if err != nil || !slices.Equal(names, []string{current, "web"}) {
		t.Fatal("default selection included history or remote services", names, err)
	}
	names, err = LocalObservationServices(project, Snapshot{}, []string{stopped, stopped})
	if err != nil || !slices.Equal(names, []string{stopped}) {
		t.Fatal("exact selection could not wait for a future invocation", names, err)
	}
	for _, test := range []struct {
		name   string
		reason failure.Reason
	}{
		{"remote", failure.AppRemoteService}, {"missing", failure.ServiceNotConfigured}, {"ivk_short", failure.ServiceNotConfigured},
	} {
		_, err := LocalObservationServices(project, snapshot, []string{test.name})
		if reason, ok := failure.ReasonOf(err); !ok || reason != test.reason {
			t.Fatal("observation selection lost its owned classification", test.name, err)
		}
	}
	names, err = LocalObservationServices(clientproject.Project{}, Snapshot{}, nil)
	if err != nil || len(names) != 0 {
		t.Fatal("an empty project invented an observation target", names, err)
	}
}
