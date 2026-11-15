package identity

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/publisher/identity/publishingtest"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestNativeTrafficClonePreservesOptionalValues(t *testing.T) {
	selection := &trafficlimits.Selection{Connections: new(48), Rate: new(3), RatePer: new("1m"), Burst: new(4), UploadBytes: new(int64(1 << 20)), DownloadBytes: new(int64(2 << 20)), TotalConnections: new(int64(0)), TotalUploadBytes: new(int64(7)), TotalDownloadBytes: new(int64(8))}
	n := &Native{NativeControl: NativeControl{Services: &unusedControl{}}}
	selected, err := n.WithTraffic(selection)
	if err != nil || !reflect.DeepEqual(selection, selected.traffic) {
		t.Fatal("typed copy changed explicit traffic values", err)
	}
	*selection.Connections, *selection.Rate, *selection.RatePer, *selection.Burst = 1, 1, "1s", 1
	*selection.UploadBytes, *selection.DownloadBytes = 1, 1
	*selection.TotalConnections, *selection.TotalUploadBytes, *selection.TotalDownloadBytes = 1, 1, 1
	limits, err := selected.traffic.Resolve(trafficlimits.Default(), trafficlimits.Ceiling())
	if err != nil || limits.Connections != 48 || limits.Rate != 3 || limits.Period().String() != "1m0s" || limits.Burst != 4 || limits.UploadBytes != 1<<20 || limits.DownloadBytes != 2<<20 || limits.TotalConnections != 0 || limits.TotalUploadBytes != 7 || limits.TotalDownloadBytes != 8 {
		t.Fatal("input pointers changed worker traffic budgets", err)
	}
	if selected, err := n.WithTraffic(nil); err != nil || selected.traffic != nil || (*trafficlimits.Selection)(nil).Clone() != nil {
		t.Fatal("omitted selection became explicit traffic limits", err)
	}
}

func TestNativeTrafficSelectionKeepsSignedRunBoundary(t *testing.T) {
	if !testutil.IsolatedPublishingTest(t) {
		return
	}
	f := publishingtest.New(t, testutil.PublishingHooks{})
	control, err := f.Owner()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.URL, f.HTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	profile, err := database.Server(t.Context(), f.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		selection *trafficlimits.Selection
	}{
		{name: "defaults"},
		{name: "explicit", selection: &trafficlimits.Selection{Connections: new(48)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, err := f.SavedService(t.Context(), test.name, controlv1.ProjectServiceConfiguration{Target: "app", Public: new(true)})
			if err != nil {
				t.Fatal(err)
			}
			n, identity, err := EnsureServiceOwner(t.Context(), profile, control, authority, service)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := n.WithTraffic(test.selection)
			if err != nil {
				t.Fatal(err)
			}
			key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
			if err != nil {
				t.Fatal(err)
			}
			access, err := selected.Access(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var prepared controlv1.ServiceRunPreparation
			for attempt := range 2 {
				run, err := selected.PrepareServiceRun(t.Context(), service.Id, key, access, ServiceDeclaration(service))
				if err != nil {
					t.Fatal(err)
				}
				if run.ServiceId != service.Id || run.IdempotencyKey != key || run.PublisherIdentityId != identity.ClientId ||
					run.PublisherGrantId != identity.GrantId || run.PublisherKeyId != identity.KeyId || n.traffic != nil ||
					!reflect.DeepEqual(selected.traffic, test.selection) {
					t.Fatal("traffic selection, exact service, retry key, or original signed grant changed")
				}
				if test.selection != nil && run.Traffic.Connections != *test.selection.Connections {
					t.Fatal("explicit worker traffic was not retained in the service run")
				}
				if attempt != 0 && (run.ServiceRunId != prepared.ServiceRunId || run.RunNumber != prepared.RunNumber) {
					t.Fatal("retry replaced an already prepared service run")
				}
				prepared = run
			}
			other, err := f.SavedService(t.Context(), "other-"+test.name, controlv1.ProjectServiceConfiguration{Target: "app", Public: new(true)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := selected.PrepareServiceRun(t.Context(), other.Id, key, access, ServiceDeclaration(other)); !errors.Is(err, ErrScope) {
				t.Fatalf("unscoped run: %v", err)
			}
			if _, err := control.PrepareServiceRun(t.Context(), other.Id, key, access, ServiceDeclaration(other)); err == nil {
				t.Fatal("the original signed access authorized another service at the control boundary")
			}
			next, err := opaqueid.New(opaqueid.IdempotencyPrefix)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := control.PrepareServiceRun(t.Context(), service.Id, next, access, ServiceDeclaration(service)); err == nil {
				t.Fatal("a different attempt replaced the current service run")
			}
			setup, err := selected.StartServiceRun(t.Context(), service.Id, prepared.ServiceRunId, access, prepared.RunNumber)
			if err != nil {
				t.Fatal(err)
			}
			if err := selected.CloseServiceRun(t.Context(), service.Id, setup.ServiceRunId, credentials.ServiceRunToken(setup.RunToken)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeTrafficSelectionsAreIndependent(t *testing.T) {
	n := &Native{NativeControl: NativeControl{Services: &unusedControl{}}}
	selection := &trafficlimits.Selection{Connections: new(48)}
	first, err := n.WithTraffic(selection)
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.WithTraffic(selection)
	if err != nil {
		t.Fatal(err)
	}
	*selection.Connections = 24
	*first.traffic.Connections = 12
	if *second.traffic.Connections != 48 || n.traffic != nil {
		t.Fatal("one worker changed another worker's selection")
	}
	defaults, err := first.WithTraffic(nil)
	if err != nil || defaults.traffic != nil || *first.traffic.Connections != 12 {
		t.Fatal("selecting defaults changed the original worker", err)
	}
	if _, err := first.WithTraffic(&trafficlimits.Selection{Connections: new(0)}); err == nil || *first.traffic.Connections != 12 {
		t.Fatal("invalid selection changed the original worker")
	}
	if _, err := (*Native)(nil).WithTraffic(selection); !errors.Is(err, ErrScope) {
		t.Fatalf("nil adapter: %v", err)
	}
}
