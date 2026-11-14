package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func targetPointer(value string) *Target { result := Target(value); return &result }

// serviceCase builds one canonical local binding, including malformed fields
// used to check the actual JSON and YAML decoding boundaries.
func serviceCase(service, protocol, binding string) string {
	declaration := map[string]any{}
	if protocol != "" {
		declaration["protocol"] = protocol
	}
	var target any
	if err := json.Unmarshal([]byte(binding), &target); err != nil {
		panic(err)
	}
	data, err := json.Marshal(map[string]any{"services": map[string]any{service: declaration}, "deployments": map[string]any{"local": map[string]any{"targets": map[string]any{service: target}}}})
	if err != nil {
		panic(err)
	}
	return string(data)
}

func TestServiceContractAcrossStaticFormats(t *testing.T) {
	for _, test := range []struct {
		name, value string
		valid       bool
	}{
		{"app default", serviceCase("web", "", `{}`), true},
		{"removed HTTP publisher pool", serviceCase("web", "", `{"publisher_pool":true}`), false},
		{"removed private publisher pool", serviceCase("db", "postgres", `{"publisher_pool":true,"type":"address","address":5432}`), false},
		{"removed disabled pool", serviceCase("web", "", `{"publisher_pool":false}`), false},
		{"named remote publisher", `{"services":{"db":{"protocol":"postgres"}},"deployments":{"cloud":{"description":"production database","targets":{"db":{"address":"db.internal:5432","access":{"team":true}}}}}}`, true},
		{"reserved local server facts", `{"deployments":{"local":{"public":true}}}`, false},
		{"publisher type removed", `{"deployments":{"cloud":{"type":"self-hosted"}}}`, false},
		{"remote app unsupported", `{"services":{"web":{}},"deployments":{"cloud":{"targets":{"web":{}}}}}`, false},
		{"remote readiness unsupported", `{"services":{"web":{}},"deployments":{"cloud":{"targets":{"web":{"address":3000,"http":{"readiness":{"path":"/health"}}}}}}}`, false},
		{"remote mounts unsupported", `{"services":{"web":{},"api":{}},"deployments":{"cloud":{"targets":{"web":{"address":3000,"http":{"paths":{"/api":"api"}}},"api":{"address":4000}}}}}`, false},
		{"mount to remote unsupported", `{"services":{"web":{},"api":{}},"deployments":{"local":{"targets":{"web":{"public_url":{},"http":{"paths":{"/api":"api"}}}}},"cloud":{"targets":{"api":{"address":4000}}}}}`, false},
		{"private webhook rejected", `{"services":{"api":{}},"webhooks":{"event":{"service":"api","path":"/event","provider":"custom"}}}`, false},
		{"remote webhook rejected", `{"services":{"api":{}},"deployments":{"cloud":{"targets":{"api":{"address":3000,"http":{}}}}},"webhooks":{"event":{"service":"api","path":"/event","provider":"custom"}}}`, false},
		{"local address webhook", `{"services":{"api":{}},"deployments":{"local":{"targets":{"api":{"public_url":{},"address":3000}}}},"webhooks":{"event":{"service":"api","path":"/event","provider":"custom"}}}`, true},
		{"local compose webhook", `{"services":{"api":{}},"deployments":{"local":{"targets":{"api":{"public_url":{},"type":"compose","service":"api","port":3000}}}},"webhooks":{"event":{"service":"api","path":"/event","provider":"custom"}}}`, true},
		{"local docker webhook", `{"services":{"api":{}},"deployments":{"local":{"targets":{"api":{"public_url":{},"type":"docker","container":"api","port":3000}}}},"webhooks":{"event":{"service":"api","path":"/event","provider":"custom"}}}`, true},
		{"private HTTP team access", serviceCase("web", "", `{"access":{"team":true}}`), true},
		{"public HTTP team access", serviceCase("web", "", `{"public_url":{},"access":{"team":true}}`), true},
		{"no root pool default", `{"publisher_pool":true,"services":{"web":{}}}`, false},
		{"no public URL pool", serviceCase("web", "", `{"public_url":{"publisher_pool":true,"access":"anonymous"}}`), false},
		{"pool boolean required", serviceCase("web", "", `{"publisher_pool":"true"}`), false},
		{"removed directory", serviceCase("web", "", `{"directory":"apps/web"}`), false},
		{"app", serviceCase("web", "", `{"type":"app"}`), true},
		{"address", serviceCase("web", "", `{"address":3000,"http":{"readiness":{"path":"/health"},"open":true}}`), true},
		{"compose", serviceCase("db", "postgres", `{"type":"compose","project":"shop-feature","file":"dev/compose.yml","service":"db","port":5432,"tls":{"hostname":"db.internal","ca":"system"}}`), true},
		{"compose defaults", serviceCase("db", "tcp", `{"type":"compose","service":"db","port":5432}`), true},
		{"docker", serviceCase("cache", "tcp", `{"type":"docker","container":"shop-cache_1","port":6379}`), true},
		{"mixed public defaults", `{"public_url":{"access":"anonymous","limits":{"http":{"concurrency":3}}},"services":{"web":{},"db":{"protocol":"tcp"}},"deployments":{"local":{"targets":{"web":{},"db":{"address":5432}}}}}`, true},
		{"public HTTPS upstream TLS name", serviceCase("web", "", `{"public_url":{},"address":"https://127.0.0.1:3000","tls":{"hostname":"web.internal","ca":"system"}}`), true},
		{"MySQL system TLS", serviceCase("db", "mysql", `{"address":3306,"tls":{}}`), true},
		{"MySQL system CA", serviceCase("db", "mysql", `{"address":"db.internal:3306","tls":{"hostname":"db.internal","ca":"system"}}`), true},
		{"RDS regional CA", serviceCase("db", "postgres", `{"address":"db.abc.us-east-1.rds.amazonaws.com:5432","tls":{"ca":"aws-rds"}}`), true},
		{"RDS CA wrong protocol", serviceCase("db", "tcp", `{"address":5432,"tls":{"ca":"aws-rds"}}`), false},
		{"PostgreSQL pass-through", serviceCase("db", "postgres", `{"address":5432}`), true},
		{"TCP name defaults to service key", serviceCase("orders", "tcp", `{"address":5432}`), true},
		{"removed private override", serviceCase("orders", "tcp", `{"private":{},"address":5432}`), false},
		{"explicit private name override", serviceCase("orders", "tcp", `{"name":"database","address":5432}`), true},
		{"conflicting default and override", `{"services":{"orders":{"protocol":"tcp"},"database":{"protocol":"tcp"}},"deployments":{"local":{"targets":{"orders":{"address":5432},"database":{"name":"orders","address":3306}}}}}`, false},
		{"duplicate mixed saved names", `{"services":{"one":{},"two":{"protocol":"tcp"}},"deployments":{"local":{"targets":{"one":{"name":"db"},"two":{"name":"db","address":3306}}}}}`, false},
		{"empty explicit private name", serviceCase("db", "tcp", `{"name":"","address":5432}`), false},
		{"invalid private name", serviceCase("db", "tcp", `{"name":"db-","address":5432}`), false},
		{"TCP with public URL", serviceCase("db", "tcp", `{"public_url":{"hostname":"https://db.example.com"},"address":5432}`), false},
		{"HTTP name override", serviceCase("web", "", `{"name":"website","public_url":{"access":"anonymous"}}`), true},
		{"HTTP exact hostname", serviceCase("web", "", `{"public_url":{"hostname":"website.example"}}`), true},
		{"duplicate exact hostnames", `{"services":{"web":{},"other":{}},"deployments":{"local":{"targets":{"web":{"public_url":{"hostname":"website.example"}},"other":{"public_url":{"hostname":"https://website.example"}}}}}}`, false},
		{"HTTP name and exact hostname", serviceCase("web", "", `{"name":"website","public_url":{"hostname":"website.example"}}`), false},
		{"removed tunnel block", serviceCase("web", "", `{"tunnel":{}}`), false},
		{"removed nested name", serviceCase("web", "", `{"public_url":{"name":"website"}}`), false},
		{"existing sshd", serviceCase("shell", "tcp", `{"address":"localhost:22"}`), true},
		{"HTTP private", `{"services":{"web":{"private":{"name":"web"}}}}`, false},
		{"old private target TLS", serviceCase("db", "postgres", `{"address":5432,"tls":{"mode":"postgres","server_name":"db.internal"}}`), false},
		{"default system CA", serviceCase("db", "postgres", `{"address":5432,"tls":{"hostname":"db.internal"}}`), true},
		{"TCP explicit direct TLS", serviceCase("db", "tcp", `{"address":5432,"tls":{}}`), true},
		{"private HTTP target TLS", serviceCase("api", "", `{"address":"https://api.internal:8443","tls":{}}`), true},
		{"private HTTP app target TLS", serviceCase("api", "", `{"type":"app","tls":{"hostname":"api.internal"}}`), true},
		{"removed nested target", serviceCase("api", "", `{"target":{"type":"address","address":3000},"tls":{"ca":"system"}}`), false},
		{"private HTTP bare address", serviceCase("api", "", `{"address":"api.internal:8443"}`), true},
		{"private publisher TLS", serviceCase("api", "", `{"address":"https://api.internal:8443","tls":{"ca":"system"}}`), true},
		{"removed TLS name", serviceCase("db", "postgres", `{"address":5432,"tls":{"server_name":"db.internal"}}`), false},
		{"removed CA file", serviceCase("db", "postgres", `{"address":5432,"tls":{"ca_file":"ca.pem"}}`), false},
		{"CA path", serviceCase("db", "postgres", `{"address":5432,"tls":{"ca":"ca.pem"}}`), false},
		{"public HTTP has no visitor target TLS", serviceCase("api", "", `{"public_url":{},"address":"https://api.internal:8443","visitor_tls":{}}`), false},
		{"app system TLS", serviceCase("web", "", `{"tls":{"ca":"system","hostname":"app.internal"}}`), true},
		{"insecure CA URL", serviceCase("db", "postgres", `{"address":5432,"tls":{"ca":"http://certs.example.com/root.pem"}}`), false},
		{"CA URL credentials", serviceCase("db", "postgres", `{"address":5432,"tls":{"ca":"https://user:password@certs.example.com/ca.pem"}}`), false},
		{"CA outside project", serviceCase("db", "postgres", `{"address":5432,"tls":{"ca_file":"../ca.pem"}}`), false},
		{"invalid TLS hostname", serviceCase("db", "mysql", `{"address":3306,"tls":{"hostname":"db/path"}}`), false},
		{"invalid CA URL port", serviceCase("db", "postgres", `{"address":5432,"tls":{"ca":"https://certs.example.com:65536/ca.pem"}}`), false},
		{"invalid TLS A-label", serviceCase("db", "postgres", `{"address":5432,"tls":{"hostname":"xn--a.example"}}`), false},
		{"HTTP database TLS mode", serviceCase("web", "", `{"address":"https://db.internal","tls":{"mode":"postgres"}}`), false},
		{"retention", `{"inspection":{"mode":"summary","retention":"720h","max_bytes":"1024MiB"}}`, true},
		{"traffic", `{"public_url":{"limits":{"http":{"rate":{"count":5,"per":"1m","burst":10}},"tcp":{"concurrency":4},"traffic":{"connections":8,"rate":5,"rate_per":"1s","burst":10,"upload_bytes":1048576,"download_bytes":2097152,"total_upload_bytes":4194304}}}}`, true},
		{"old root publish", `{"publish":{"target":3000}}`, false},
		{"old root readiness", `{"readiness":{"path":"/"}}`, false},
		{"old service publish", serviceCase("web", "", `{"publish":{"target":3000}}`), false},
		{"old service readiness", serviceCase("web", "", `{"readiness":{"path":"/"}}`), false},
		{"old mounts", serviceCase("web", "", `{"paths":{"/api":"api"}}`), false},
		{"old limits", `{"public_url":{"limits":{"concurrency":2}}}`, false},
		{"old browser opening", `{"public_url":{"open":true}}`, false},
		{"visitor TLS", serviceCase("web", "", `{"address":3000,"tls":{"passthrough":true}}`), false},
		{"app discovery fields", serviceCase("web", "", `{"type":"app","port":3000}`), false},
		{"address discovery fields", serviceCase("web", "", `{"address":3000,"service":"web"}`), false},
		{"missing address", serviceCase("web", "", `{"type":"address"}`), false},
		{"compose project optional", serviceCase("web", "", `{"type":"compose","file":"compose.yml","service":"web","port":3000}`), true},
		{"compose outside project", serviceCase("web", "", `{"type":"compose","project":"shop","file":"../compose.yml","service":"web","port":3000}`), false},
		{"compose absolute", serviceCase("web", "", `{"type":"compose","project":"shop","file":"/compose.yml","service":"web","port":3000}`), false},
		{"compose foreign field", serviceCase("web", "", `{"type":"compose","project":"shop","file":"compose.yml","service":"web","port":3000,"container":"web"}`), false},
		{"docker option", serviceCase("web", "", `{"type":"docker","container":"--all","port":3000}`), false},
		{"docker filter", serviceCase("web", "", `{"type":"docker","container":"name=web","port":3000}`), false},
		{"docker slash", serviceCase("web", "", `{"type":"docker","container":"/web","port":3000}`), false},
		{"docker foreign field", serviceCase("web", "", `{"type":"docker","container":"web","port":3000,"file":"compose.yml"}`), false},
		{"zero port", serviceCase("db", "tcp", `{"type":"docker","container":"db","port":0}`), false},
		{"large port", serviceCase("db", "tcp", `{"type":"docker","container":"db","port":65536}`), false},
		{"TCP app", serviceCase("db", "tcp", `{"type":"app"}`), false},
		{"TCP HTTP", serviceCase("db", "tcp", `{"address":5432,"http":{"open":false}}`), false},
		{"HTTP TCP limits", serviceCase("web", "", `{"public_url":{"limits":{"tcp":{"total":1}}}}`), false},
		{"TLS plain HTTP", serviceCase("web", "", `{"address":3000,"tls":{}}`), false},
		{"TLS invalid name", serviceCase("db", "postgres", `{"address":5432,"tls":{"hostname":"db/path"}}`), false},
		{"null target", serviceCase("web", "", `null`), false},
		{"null variant field", serviceCase("web", "", `{"type":"app","address":null}`), false},
		{"numeric Docker identifier", serviceCase("web", "", `{"type":"docker","container":123,"port":3000}`), false},
		{"short retention", `{"inspection":{"retention":"59s"}}`, false},
		{"long retention", `{"inspection":{"retention":"721h"}}`, false},
		{"small inspection", `{"inspection":{"max_bytes":"1023KiB"}}`, false},
		{"large inspection", `{"inspection":{"max_bytes":"2GiB"}}`, false},
		{"overflow inspection", `{"inspection":{"max_bytes":"9999999999999999999999GiB"}}`, false},
		{"unsafe count", `{"public_url":{"limits":{"http":{"total":9007199254740992}}}}`, false},
		{"unsafe traffic", `{"public_url":{"limits":{"traffic":{"total_upload_bytes":9007199254740992}}}}`, false},
		{"removed byte total", `{"public_url":{"limits":{"traffic":{"total_bytes":1000}}}}`, false},
		{"removed byte rate", `{"public_url":{"limits":{"traffic":{"rate":{"bytes":1000,"per":"1s"}}}}}`, false},
		{"partial root rate", `{"public_url":{"limits":{"tcp":{"rate":{"count":1}}}}}`, false},
		{"zero traffic period", `{"public_url":{"limits":{"traffic":{"rate_per":"0s"}}}}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal([]byte(test.value), &value); err != nil {
				t.Fatal(err)
			}
			// preserve integer YAML tags rather than marshaling float64 exponents.
			integerValues(value)
			document := map[string]any{"version": 1, "tnl": value}
			jsonData, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			yamlData, err := yaml.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			for ext, data := range map[string][]byte{"json": jsonData, "yml": yamlData} {
				file := filepath.Join(t.TempDir(), "tnl."+ext)
				if err := os.WriteFile(file, data, 0600); err != nil {
					t.Fatal(err)
				}
				_, err := LoadDocument(file)
				if (err == nil) != test.valid {
					t.Fatalf("%s valid=%v, want %v: %v", ext, err == nil, test.valid, err)
				}
			}
		})
	}
}

func integerValues(value map[string]any) {
	for key, child := range value {
		switch n := child.(type) {
		case float64:
			value[key] = int64(n)
		case map[string]any:
			integerValues(n)
		}
	}
}

func TestInspectionAndLimitsMergeWithoutChangingDefaults(t *testing.T) {
	retention := Duration(24 * time.Hour)
	size := ByteSize(64 << 20)
	mode := InspectionSummary
	none := InspectionNone
	merged := MergeInspection(&Inspection{Mode: &mode, Retention: &retention, MaxBytes: &size}, &Inspection{Mode: &none})
	if *merged.Mode != InspectionNone || merged.Retention != &retention || merged.MaxBytes != &size {
		t.Fatalf("inspection: %#v", merged)
	}
	count, burst := 5, 10
	per := Duration(time.Second)
	bytes := int64(1 << 20)
	base := &Limits{HTTP: &WorkLimits{Rate: &Rate{Count: &count, Per: &per}}, Traffic: &TrafficLimits{UploadBytes: &bytes, RatePer: &per}}
	result := MergeLimits(base, &Limits{HTTP: &WorkLimits{Rate: &Rate{Burst: &burst}}})
	result.HTTP.Rate.Per = nil
	result.Traffic.RatePer = nil
	if base.HTTP.Rate.Per == nil || base.Traffic.RatePer == nil {
		t.Fatal("merge mutated project defaults")
	}
}

func TestNativeResolutionHelpersSelectProtocolAndInspection(t *testing.T) {
	count, connections, burst := 5, 2, 10
	per := Duration(time.Second)
	limits := &Limits{HTTP: &WorkLimits{Rate: &Rate{Count: &count, Per: &per, Burst: &burst}}, TCP: &WorkLimits{Total: &connections}}
	http, err := ResolveWorkLimits(limits, "http")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := ResolveWorkLimits(limits, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if http.RateRequests != 5 || http.RateBurst != 10 || http.RatePer != time.Second || tcp.Requests != 2 || tcp.RateRequests != 0 {
		t.Fatalf("HTTP=%+v TCP=%+v", http, tcp)
	}
	policy, err := ResolveInspection(nil, "tcp")
	if err != nil || policy.Mode != "none" || policy.Retention != 24*time.Hour || policy.MaxBytes != 64<<20 {
		t.Fatalf("inspection=%+v: %v", policy, err)
	}
	mode := InspectionSummary
	policy, err = ResolveInspection(&Inspection{Mode: &mode}, "postgres")
	if err != nil || policy.Mode != "none" {
		t.Fatalf("TCP inspection=%+v: %v", policy, err)
	}
	policy, err = ResolveInspection(nil, "http")
	if err != nil || policy.Mode != "summary" {
		t.Fatalf("HTTP inspection=%+v: %v", policy, err)
	}
	policy, err = ResolveInspection(nil, "ssh")
	if err == nil {
		t.Fatalf("removed SSH protocol accepted: %+v", policy)
	}
	if MatchesDockerIdentifier("abc123", "abc123456789", "/database") || !MatchesDockerIdentifier("database", "abc123456789", "/database") {
		t.Fatal("Docker exact identity matching failed")
	}
}

func TestServiceNameDefaultsToValidatedServiceKey(t *testing.T) {
	protocol := "tcp"
	service := Service{Protocol: &protocol, Target: &ServiceTarget{Type: "address", Address: targetPointer("5432")}}
	if got := ServiceName("orders", service); got != "orders" {
		t.Fatalf("default private name = %q", got)
	}
	override := "database"
	service.Name = &override
	if got := ServiceName("orders", service); got != override {
		t.Fatalf("explicit private name = %q", got)
	}
	if err := ValidateTNL(TNL{Services: Services{"orders": service}}); err != nil {
		t.Fatal(err)
	}
}

func TestSavedServiceNamesAndExactHostnamesHaveDeterministicCollisions(t *testing.T) {
	name, hostname, url := "database", "web.example", "https://web.example"
	for _, test := range []struct {
		services Services
		want     string
	}{
		{Services{"beta": {Name: &name}, "alpha": {Name: &name}}, `services.beta: saved name "database" is already used by services.alpha`},
		{Services{"beta": {Tunnel: &Tunnel{PublicURL: &hostname}}, "alpha": {Tunnel: &Tunnel{PublicURL: &url}}}, "services.beta: public_url.hostname is already used by services.alpha"},
	} {
		if err := ValidateTNL(TNL{Services: test.services}); err == nil || err.Error() != test.want {
			t.Fatalf("collision = %v, want %s", err, test.want)
		}
	}
}

func TestTrafficSelectionUsesIndependentControlFields(t *testing.T) {
	connections, rate, burst := 12, 7, 15
	upload, download, totalDownload := int64(1<<20), int64(2<<20), int64(10<<20)
	period := Duration(2 * time.Second)
	root := &Limits{Traffic: &TrafficLimits{Connections: &connections, Rate: &rate, RatePer: &period, UploadBytes: &upload}}
	service := &Limits{Traffic: &TrafficLimits{Burst: &burst, DownloadBytes: &download, TotalDownloadBytes: &totalDownload}}
	selection, err := ResolveTrafficSelection(MergeLimits(root, service))
	if err != nil || selection.Connections != &connections || selection.Rate != &rate || selection.RatePer == nil || *selection.RatePer != "2s" || selection.Burst != &burst || selection.UploadBytes != &upload || selection.DownloadBytes != &download || selection.TotalDownloadBytes != &totalDownload || selection.TotalUploadBytes != nil {
		t.Fatalf("traffic selection = %+v: %v", selection, err)
	}
	if root.Traffic.DownloadBytes != nil || root.Traffic.Burst != nil {
		t.Fatal("service override changed root traffic limits")
	}
	if empty, err := ResolveTrafficSelection(nil); err != nil || empty != nil {
		t.Fatalf("empty traffic selection = %+v: %v", empty, err)
	}
}

func TestYAMLRejectsCoercionsInAnchorsAndRecursiveAliases(t *testing.T) {
	for _, contents := range []string{
		"version: 1\ntnl:\n  services:\n    web:\n      target: &target\n        type: docker\n        container: 123\n        port: 3000\n    other:\n      target:\n        <<: *target\n",
		"version: 1\ntnl: &root\n  services: *root\n",
	} {
		file := filepath.Join(t.TempDir(), "tnl.yml")
		if err := os.WriteFile(file, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDocument(file); err == nil {
			t.Fatal("YAML coercion or recursive alias was accepted")
		}
	}
}
