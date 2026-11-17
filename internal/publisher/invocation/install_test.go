package invocation

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestInstalledHTTPPreparationKeepsRequestLimitsCapacityAndTrafficSeparate(t *testing.T) {
	f := newServiceSetupFixture(t, "app.member.example")
	captured, err := targettrust.NewDeclaration("app.internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := captured.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	flags := InstallationOptions{PublicOptions: PublicOptions{
		Limits:             applicationlimits.Limits{Requests: 20, Concurrency: 3, RateRequests: 7, RatePer: time.Second, RateBurst: 9},
		RequirePostQuantum: new(true)},
		StreamCapacity: 64, Traffic: &trafficlimits.Selection{Connections: new(11), UploadBytes: new(int64(64 << 10))}, ReadinessPath: "/health"}
	prefixes := []string{"192.0.2.0/24", "10.0.0.0/8"}
	policy, err := resolveVisitorAccess(t.Context(), f.services.routes, nil, true, prefixes)
	if err != nil {
		t.Fatal(err)
	}
	plan := target.TargetPlan{Protocol: config.ProtocolHTTP, Target: "https://127.0.0.1:3000", Trust: trust}
	saved, err := prepareInstalledHTTPService(t.Context(), f.services, flags, plan, policy)
	if err != nil {
		t.Fatal(err)
	}
	declaration := f.declaration
	if declaration.Protocol == nil || *declaration.Protocol != controlv1.ServiceProtocolHTTP || declaration.Public == nil || !*declaration.Public ||
		declaration.Ephemeral == nil || *declaration.Ephemeral || declaration.RequirePostQuantum == nil || !*declaration.RequirePostQuantum || declaration.Target != plan.Target ||
		saved.Endpoint.Hostname != f.services.hostname || saved.Id != f.saved.Id || f.creates != 1 || f.enrollments != 0 {
		t.Fatal("retained declaration changed publication intent", declaration)
	}
	http := declaration.Http
	if http == nil || http.Limits == nil || http.Limits.Total == nil || *http.Limits.Total != 20 || http.Limits.Concurrency == nil || *http.Limits.Concurrency != 3 ||
		http.Limits.Rate == nil || http.Limits.Rate.Count != 7 || http.Limits.Rate.Per != "1s" || http.Limits.Rate.Burst == nil || *http.Limits.Rate.Burst != 9 ||
		http.Readiness == nil || http.Readiness.Path != "/health" {
		t.Fatal("retained HTTP request policy was dropped", http)
	}
	if flags.StreamCapacity != 64 || declaration.Traffic == nil || declaration.Traffic.Connections == nil || *declaration.Traffic.Connections != 11 ||
		declaration.Traffic.UploadBytes == nil || *declaration.Traffic.UploadBytes != 64<<10 {
		t.Fatal("physical streams and ingress traffic were mixed with HTTP request limits")
	}
	if declaration.TargetTls == nil || declaration.TargetTls.Digest != captured.Digest || declaration.TargetTls.Digest == trust.Digest {
		t.Fatal("retained target declaration used the service snapshot digest")
	}
	if http.Access == nil || http.Access.Mode == nil || *http.Access.Mode != controlv1.Anonymous || http.Access.Ip == nil ||
		!reflect.DeepEqual(*http.Access.Ip, []string{"10.0.0.0/8", "192.0.2.0/24"}) || !reflect.DeepEqual(prefixes, []string{"192.0.2.0/24", "10.0.0.0/8"}) {
		t.Fatal("HTTP access was lost or mutated its caller", http.Access)
	}
	*flags.Traffic.Connections = 99
	if *declaration.Traffic.Connections != 11 {
		t.Fatal("retained traffic shares mutable caller state")
	}
}

func TestInstalledHTTPPreparationPreservesOmittedPolicy(t *testing.T) {
	f := newServiceSetupFixture(t, "app.member.example")
	_, err := prepareInstalledHTTPService(t.Context(), f.services, InstallationOptions{},
		target.TargetPlan{Protocol: config.ProtocolHTTP, Target: "http://127.0.0.1:3000"}, resolvedVisitorAccess{})
	if err != nil {
		t.Fatal(err)
	}
	declaration := f.declaration
	if declaration.TargetTls != nil || declaration.Traffic != nil ||
		declaration.Http != nil && (declaration.Http.Access != nil || declaration.Http.Limits != nil || declaration.Http.Readiness != nil) {
		t.Fatal("local defaults became an explicit retained policy", declaration)
	}
}

func TestInstalledHTTPAndForegroundPreparationShareServiceAndKeepSigningIdentity(t *testing.T) {
	for _, installFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "foreground then install", true: "install then foreground"}[installFirst], func(t *testing.T) {
			f := newForegroundFixture(t)
			install := func() controlv1.Service {
				t.Helper()
				enrollments, redemptions := f.enrollments, f.redemptions
				saved, err := prepareInstalledHTTPService(t.Context(), f.services, InstallationOptions{ReadinessPath: "/health"}, foregroundPlan(), resolvedVisitorAccess{})
				if err != nil || f.enrollments != enrollments || f.redemptions != redemptions {
					t.Fatal("installation preparation replaced signing credentials or failed to select the service", saved, err)
				}
				return saved
			}
			foreground := func() controlv1.Service {
				t.Helper()
				native, saved, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := native.Access(t.Context()); err != nil {
					t.Fatal("original publisher signing key no longer authenticates", err)
				}
				return saved
			}
			var first, second controlv1.Service
			if installFirst {
				first, second = install(), foreground()
			} else {
				first, second = foreground(), install()
			}
			key := bytes.Clone(f.public)
			last := foreground()
			if f.creates != 1 || first.Id != second.Id || first.Id != last.Id || first.Name != second.Name ||
				first.Endpoint.Hostname != second.Endpoint.Hostname || f.declaration.Target != foregroundPlan().Target ||
				f.declaration.Http == nil || f.declaration.Http.Readiness == nil || f.declaration.Http.Readiness.Path != "/health" ||
				f.enrollments != 1 || f.redemptions != 1 || !bytes.Equal(key, f.public) {
				t.Fatal("switching publication owners changed service, installation settings, or signing credentials", first, second, last,
					f.creates, f.enrollments, f.redemptions, f.declaration)
			}
		})
	}
}

func TestInstalledHTTPPreparationRecreatesDeletedService(t *testing.T) {
	f := newServiceSetupFixture(t, "reinstall.member.example")
	first, err := prepareInstalledHTTPService(t.Context(), f.services, InstallationOptions{}, foregroundPlan(), resolvedVisitorAccess{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.services.routes.DeleteService(t.Context(), first.Id, controlv1.DeleteServiceParams{ExpectedServiceRevision: &first.ServiceRevision}); err != nil {
		t.Fatal(err)
	}
	second, err := prepareInstalledHTTPService(t.Context(), f.services, InstallationOptions{}, foregroundPlan(), resolvedVisitorAccess{})
	if err != nil || first.Id == second.Id || first.Name != second.Name || f.creates != 2 ||
		len(f.createKeys) != 2 || f.createKeys[0] == f.createKeys[1] {
		t.Fatal("reinstallation reused a retired lifetime's creation key", first, second, f.createKeys, err)
	}
}

func TestInstalledHTTPPreparationRetainsPolicyAcrossUpdateRetry(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost reply", true: "conflict"}[conflict], func(t *testing.T) {
			f := newForegroundFixture(t)
			flags := InstallationOptions{PublicOptions: PublicOptions{RequirePostQuantum: new(true),
				Limits: applicationlimits.Limits{Requests: 20}}, ReadinessPath: "/health",
				Traffic: &trafficlimits.Selection{Connections: new(11)}}
			first, err := prepareInstalledHTTPService(t.Context(), f.services, flags, foregroundPlan(),
				resolvedVisitorAccess{explicit: true, access: controlv1.Anonymous})
			if err != nil {
				t.Fatal(err)
			}
			f.saved.PublisherPool = true
			previous := f.before
			if conflict {
				f.before = func(r *http.Request) (*http.Response, bool) {
					if response, handled := previous(r); handled {
						return response, true
					}
					if r.Method == http.MethodPut {
						f.before = previous
						f.declaration.Http.Limits.Total = new(80)
						return serviceTestResponse(r, 409, controlv1.Problem{Code: controlv1.Conflict, Status: 409}), true
					}
					return nil, false
				}
			} else {
				f.afterUpdate = func() error {
					f.afterUpdate = nil
					f.declaration.Http.Limits.Total = new(80)
					return io.ErrUnexpectedEOF
				}
			}
			flags = InstallationOptions{PublicOptions: PublicOptions{Limits: applicationlimits.Limits{Concurrency: 7}}}
			plan := foregroundPlan()
			plan.Target = "http://127.0.0.1:4000"
			saved, err := prepareInstalledHTTPService(t.Context(), f.services, flags, plan, resolvedVisitorAccess{})
			if err != nil || saved.Id != first.Id || f.creates != 1 || !saved.PublisherPool || !saved.RequirePostQuantum ||
				f.declaration.Target != plan.Target || *f.declaration.Http.Access.Mode != controlv1.Anonymous ||
				*f.declaration.Http.Limits.Total != 80 || *f.declaration.Http.Limits.Concurrency != 7 ||
				f.declaration.Http.Readiness.Path != "/health" || *f.declaration.Traffic.Connections != 11 {
				t.Fatal("installation retry replaced service identity or unrelated current policy", saved, f.declaration, err)
			}
		})
	}
}

func TestInstalledHTTPPreparationRecoversLostCreateReplyWithoutAnotherService(t *testing.T) {
	f := newServiceSetupFixture(t, "lost-install.member.example")
	inventories := 0
	f.before = func(r *http.Request) (*http.Response, bool) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/services" {
			inventories++
		}
		return nil, false
	}
	lost := errors.New("lost creation reply")
	f.afterCreate = func() error {
		f.afterCreate = nil
		return errors.Join(io.ErrUnexpectedEOF, lost)
	}
	saved, err := prepareInstalledHTTPService(t.Context(), f.services, InstallationOptions{}, foregroundPlan(), resolvedVisitorAccess{})
	if err != nil || saved.Id != f.saved.Id || f.creates != 1 || len(f.createKeys) != 2 ||
		f.createKeys[0] != f.createKeys[1] || len(f.creations) != 1 || inventories != 0 || f.updates != 0 ||
		f.enrollments != 0 || f.redemptions != 0 {
		t.Fatal("installation did not recover one committed service through the same-key reservation", saved, f.creates, f.createKeys, inventories, f.updates, err)
	}
	for range 2 {
		retry, err := prepareInstalledHTTPService(t.Context(), f.services, InstallationOptions{}, foregroundPlan(), resolvedVisitorAccess{})
		if err != nil || retry.Id != saved.Id || f.creates != 1 || f.updates != 0 || inventories != 0 ||
			f.enrollments != 0 || f.redemptions != 0 {
			t.Fatal("installation retry changed the recovered service", retry, err)
		}
	}
	if len(f.createKeys) != 4 || len(f.creations) != 3 ||
		f.createKeys[2] == f.createKeys[0] || f.createKeys[3] == f.createKeys[0] || f.createKeys[2] == f.createKeys[3] {
		t.Fatal("independent preparation retries did not record distinct receipts on the same lifetime", f.createKeys)
	}
}
