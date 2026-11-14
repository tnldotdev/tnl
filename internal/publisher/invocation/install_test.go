package invocation

import (
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestInstalledHTTPDeclarationKeepsRequestLimitsCapacityAndTrafficSeparate(t *testing.T) {
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
		StreamCapacity: 64, Traffic: &trafficlimits.Selection{Connections: new(11), UploadBytes: new(int64(1024))}, ReadinessPath: "/health"}
	prefixes := []string{"192.0.2.0/24", "10.0.0.0/8"}
	policy := resolvedVisitorAccess{explicit: true, access: controlv1.Anonymous, prefixes: prefixes}
	plan := target.TargetPlan{Protocol: config.ProtocolHTTP, Target: "https://127.0.0.1:3000", Trust: trust}
	declaration, err := installedHTTPDeclaration(flags, "app", "domain", "app.example", plan, policy)
	if err != nil {
		t.Fatal(err)
	}
	if declaration.Protocol == nil || *declaration.Protocol != controlv1.ServiceProtocolHTTP || declaration.Public == nil || !*declaration.Public ||
		declaration.Ephemeral == nil || *declaration.Ephemeral || declaration.RequirePostQuantum == nil || !*declaration.RequirePostQuantum || declaration.Target != plan.Target {
		t.Fatal("retained declaration changed publication intent", declaration)
	}
	http := declaration.Http
	if http == nil || http.Limits == nil || http.Limits.Total == nil || *http.Limits.Total != 20 || http.Limits.Concurrency == nil || *http.Limits.Concurrency != 3 ||
		http.Limits.Rate == nil || http.Limits.Rate.Count != 7 || http.Limits.Rate.Per != "1s" || http.Limits.Rate.Burst == nil || *http.Limits.Rate.Burst != 9 ||
		http.Readiness == nil || http.Readiness.Path != "/health" {
		t.Fatal("retained HTTP request policy was dropped", http)
	}
	if flags.StreamCapacity != 64 || declaration.Traffic == nil || declaration.Traffic.Connections == nil || *declaration.Traffic.Connections != 11 ||
		declaration.Traffic.UploadBytes == nil || *declaration.Traffic.UploadBytes != 1024 {
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

func TestInstalledHTTPDeclarationPreservesOmittedPolicy(t *testing.T) {
	declaration, err := installedHTTPDeclaration(InstallationOptions{}, "app", "domain", "app.example",
		target.TargetPlan{Protocol: config.ProtocolHTTP, Target: "http://127.0.0.1:3000"}, resolvedVisitorAccess{})
	if err != nil {
		t.Fatal(err)
	}
	if declaration.TargetTls != nil || declaration.Traffic != nil || declaration.Http.Access != nil || declaration.Http.Limits != nil || declaration.Http.Readiness != nil {
		t.Fatal("local defaults became an explicit retained policy", declaration)
	}
}

func TestInstalledHTTPCreateRetriesKeepOneServiceSelection(t *testing.T) {
	values := []string{"https://control.example", "team", "domain", "app.example", "app", "worktree"}
	key := installedHTTPCreateKey(values[0], values[1], values[2], values[3], values[4], values[5])
	if !opaqueid.Valid(key, opaqueid.IdempotencyPrefix) || key != installedHTTPCreateKey(values[0], values[1], values[2], values[3], values[4], values[5]) {
		t.Fatal("retry changed its service-create operation")
	}
	for index := range values {
		changed := append([]string(nil), values...)
		changed[index] += "-other"
		if key == installedHTTPCreateKey(changed[0], changed[1], changed[2], changed[3], changed[4], changed[5]) {
			t.Fatal("different service selections share a create operation", index)
		}
	}
}
