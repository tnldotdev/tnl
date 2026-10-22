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

func TestServiceContractAcrossStaticFormats(t *testing.T) {
	for _, test := range []struct {
		name, value string
		valid       bool
	}{
		{"app default", `{"services":{"web":{}}}`, true},
		{"removed HTTP publisher pool", `{"services":{"web":{"publisher_pool":true}}}`, false},
		{"removed private publisher pool", `{"services":{"db":{"publisher_pool":true,"protocol":"postgres","target":{"type":"address","address":5432}}}}`, false},
		{"removed disabled pool", `{"services":{"web":{"publisher_pool":false}}}`, false},
		{"named remote publisher", `{"publisher_groups":{"cloud":{"description":"production database"}},"services":{"db":{"publisher_group":"cloud","protocol":"postgres","target":{"type":"address","address":"db.internal:5432"},"access":{"team":true}}}}`, true},
		{"reserved local publisher", `{"publisher_groups":{"local":{}}}`, false},
		{"publisher type removed", `{"publisher_groups":{"cloud":{"type":"self-hosted"}}}`, false},
		{"unknown publisher", `{"services":{"web":{"publisher_group":"unknown"}}}`, false},
		{"remote app unsupported", `{"publisher_groups":{"cloud":{}},"services":{"web":{"publisher_group":"cloud"}}}`, false},
		{"remote readiness unsupported", `{"publisher_groups":{"cloud":{}},"services":{"web":{"publisher_group":"cloud","target":{"type":"address","address":3000},"http":{"readiness":{"path":"/health"}}}}}`, false},
		{"remote mounts unsupported", `{"publisher_groups":{"cloud":{}},"services":{"web":{"publisher_group":"cloud","target":{"type":"address","address":3000},"http":{"paths":{"/api":"api"}}},"api":{}}}`, false},
		{"mount to remote unsupported", `{"publisher_groups":{"cloud":{}},"services":{"web":{"public_url":{},"http":{"paths":{"/api":"api"}}},"api":{"publisher_group":"cloud","target":{"type":"address","address":4000}}}}`, false},
		{"private webhook rejected", `{"services":{"api":{}},"webhooks":{"event":{"service":"api","path":"/event","provider":"custom"}}}`, false},
		{"remote webhook rejected", `{"publisher_groups":{"cloud":{}},"services":{"api":{"publisher_group":"cloud","target":{"type":"address","address":3000},"http":{}}},"webhooks":{"event":{"service":"api","path":"/event","provider":"custom"}}}`, false},
		{"local address webhook", `{"services":{"api":{"public_url":{},"target":{"type":"address","address":3000}}},"webhooks":{"event":{"service":"api","path":"/event","provider":"custom"}}}`, true},
		{"local compose webhook", `{"services":{"api":{"public_url":{},"target":{"type":"compose","service":"api","port":3000}}},"webhooks":{"event":{"service":"api","path":"/event","provider":"custom"}}}`, true},
		{"local docker webhook", `{"services":{"api":{"public_url":{},"target":{"type":"docker","container":"api","port":3000}}},"webhooks":{"event":{"service":"api","path":"/event","provider":"custom"}}}`, true},
		{"private HTTP team access", `{"services":{"web":{"access":{"team":true}}}}`, true},
		{"public HTTP team access", `{"services":{"web":{"public_url":{},"access":{"team":true}}}}`, true},
		{"no root pool default", `{"publisher_pool":true,"services":{"web":{}}}`, false},
		{"no public URL pool", `{"services":{"web":{"public_url":{"publisher_pool":true,"access":"anonymous"}}}}`, false},
		{"pool boolean required", `{"services":{"web":{"publisher_pool":"true"}}}`, false},
		{"removed directory", `{"services":{"web":{"directory":"apps/web"}}}`, false},
		{"app", `{"services":{"web":{"target":{"type":"app"}}}}`, true},
		{"address", `{"services":{"web":{"target":{"type":"address","address":3000},"http":{"readiness":{"path":"/health"},"open":true}}}}`, true},
		{"compose", `{"services":{"db":{"protocol":"postgres","target":{"type":"compose","project":"shop-feature","file":"dev/compose.yml","service":"db","port":5432,"tls":{"server_name":"db.internal","ca_file":"certs/ca.pem"}}}}}`, true},
		{"compose defaults", `{"services":{"db":{"protocol":"tcp","target":{"type":"compose","service":"db","port":5432}}}}`, true},
		{"docker", `{"services":{"cache":{"protocol":"tcp","target":{"type":"docker","container":"shop-cache_1","port":6379}}}}`, true},
		{"removed publisher placement", `{"publisher_group":{"type":"compose","service":"publisher"},"services":{"web":{"target":{"type":"app"}}}}`, false},
		{"mixed public defaults", `{"public_url":{"access":"anonymous","limits":{"http":{"concurrency":3}}},"services":{"web":{},"db":{"protocol":"tcp","target":{"type":"address","address":5432}}}}`, true},
		{"public HTTPS upstream TLS name", `{"services":{"web":{"public_url":{},"target":{"type":"address","address":"https://127.0.0.1:3000","tls":{"server_name":"web.internal","ca_file":"certs/ca.pem"}}}}}`, true},
		{"MySQL system TLS", `{"services":{"db":{"protocol":"mysql","target":{"type":"address","address":3306,"tls":{}}}}}`, true},
		{"MySQL custom CA", `{"services":{"db":{"protocol":"mysql","target":{"type":"address","address":"db.internal:3306","tls":{"server_name":"db.internal","ca_file":"certs/ca.pem"}}}}}`, true},
		{"PostgreSQL pass-through", `{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":5432}}}}`, true},
		{"TCP name defaults to service key", `{"services":{"orders":{"protocol":"tcp","target":{"type":"address","address":5432}}}}`, true},
		{"removed private override", `{"services":{"orders":{"protocol":"tcp","private":{},"target":{"type":"address","address":5432}}}}`, false},
		{"explicit private name override", `{"services":{"orders":{"protocol":"tcp","name":"database","target":{"type":"address","address":5432}}}}`, true},
		{"conflicting default and override", `{"services":{"orders":{"protocol":"tcp","target":{"type":"address","address":5432}},"database":{"protocol":"tcp","name":"orders","target":{"type":"address","address":3306}}}}`, false},
		{"duplicate mixed saved names", `{"services":{"one":{"name":"db"},"two":{"protocol":"tcp","name":"db","target":{"type":"address","address":3306}}}}`, false},
		{"empty explicit private name", `{"services":{"db":{"protocol":"tcp","name":"","target":{"type":"address","address":5432}}}}`, false},
		{"invalid private name", `{"services":{"db":{"protocol":"tcp","name":"db-","target":{"type":"address","address":5432}}}}`, false},
		{"TCP with public URL", `{"services":{"db":{"protocol":"tcp","public_url":{"hostname":"https://db.example.com"},"target":{"type":"address","address":5432}}}}`, false},
		{"HTTP name override", `{"services":{"web":{"name":"website","public_url":{"access":"anonymous"}}}}`, true},
		{"HTTP exact hostname", `{"services":{"web":{"public_url":{"hostname":"website.example"}}}}`, true},
		{"duplicate exact hostnames", `{"services":{"web":{"public_url":{"hostname":"website.example"}},"other":{"public_url":{"hostname":"https://website.example"}}}}`, false},
		{"HTTP name and exact hostname", `{"services":{"web":{"name":"website","public_url":{"hostname":"website.example"}}}}`, false},
		{"removed tunnel block", `{"services":{"web":{"tunnel":{}}}}`, false},
		{"removed nested name", `{"services":{"web":{"public_url":{"name":"website"}}}}`, false},
		{"existing sshd", `{"services":{"shell":{"protocol":"tcp","target":{"type":"address","address":"localhost:22"}}}}`, true},
		{"HTTP private", `{"services":{"web":{"private":{"name":"web"}}}}`, false},
		{"old private target TLS", `{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":5432,"tls":{"mode":"postgres","server_name":"db.internal"}}}}}`, false},
		{"missing CA", `{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":5432},"tls":{"hostname":"db.internal"}}}}`, false},
		{"TCP explicit direct TLS", `{"services":{"db":{"protocol":"tcp","target":{"type":"address","address":5432,"tls":{}}}}}`, true},
		{"private HTTP target TLS", `{"services":{"api":{"target":{"type":"address","address":"https://api.internal:8443","tls":{}}}}}`, true},
		{"private HTTP app target TLS", `{"services":{"api":{"target":{"type":"app","tls":{"server_name":"api.internal"}}}}}`, true},
		{"removed service TLS", `{"services":{"api":{"target":{"type":"address","address":3000},"tls":{"ca":"system"}}}}`, false},
		{"private HTTP bare address", `{"services":{"api":{"target":{"type":"address","address":"api.internal:8443"}}}}`, true},
		{"private publisher TLS", `{"services":{"api":{"target":{"type":"address","address":"https://api.internal:8443","tls":{"ca_file":"ca.pem"}}}}}`, true},
		{"public HTTP has no visitor target TLS", `{"services":{"api":{"public_url":{},"target":{"type":"address","address":"https://api.internal:8443"},"tls":{"ca":"system"}}}}`, false},
		{"HTTP database TLS", `{"services":{"web":{"tls":{"ca":"system"}}}}`, false},
		{"insecure CA URL", `{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":5432},"tls":{"ca":"http://certs.example.com/root.pem"}}}}`, false},
		{"CA URL credentials", `{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":5432},"tls":{"ca":"https://user:password@certs.example.com/ca.pem"}}}}`, false},
		{"CA outside project", `{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":5432},"tls":{"ca":"../ca.pem"}}}}`, false},
		{"invalid TLS hostname", `{"services":{"db":{"protocol":"mysql","target":{"type":"address","address":3306},"tls":{"hostname":"db/path","ca":"system"}}}}`, false},
		{"invalid CA URL port", `{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":5432},"tls":{"ca":"https://certs.example.com:65536/ca.pem"}}}}`, false},
		{"invalid TLS A-label", `{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":5432},"tls":{"hostname":"xn--a.example","ca":"system"}}}}`, false},
		{"HTTP database TLS mode", `{"services":{"web":{"target":{"type":"address","address":"https://db.internal","tls":{"mode":"postgres"}}}}}`, false},
		{"retention", `{"inspection":{"mode":"summary","retention":"720h","max_bytes":"1024MiB"}}`, true},
		{"traffic", `{"public_url":{"limits":{"http":{"rate":{"count":5,"per":"1m","burst":10}},"tcp":{"concurrency":4},"traffic":{"connections":8,"rate":5,"rate_per":"1s","burst":10,"upload_bytes":1048576,"download_bytes":2097152,"total_upload_bytes":4194304}}}}`, true},
		{"old root publish", `{"publish":{"target":3000}}`, false},
		{"old root readiness", `{"readiness":{"path":"/"}}`, false},
		{"old service publish", `{"services":{"web":{"publish":{"target":3000}}}}`, false},
		{"old service readiness", `{"services":{"web":{"readiness":{"path":"/"}}}}`, false},
		{"old mounts", `{"services":{"web":{"paths":{"/api":"api"}},"api":{}}}`, false},
		{"old limits", `{"public_url":{"limits":{"concurrency":2}}}`, false},
		{"old browser opening", `{"public_url":{"open":true}}`, false},
		{"visitor TLS", `{"services":{"web":{"target":{"type":"address","address":3000,"tls":{"passthrough":true}}}}}`, false},
		{"app discovery fields", `{"services":{"web":{"target":{"type":"app","port":3000}}}}`, false},
		{"address discovery fields", `{"services":{"web":{"target":{"type":"address","address":3000,"service":"web"}}}}`, false},
		{"missing address", `{"services":{"web":{"target":{"type":"address"}}}}`, false},
		{"compose project optional", `{"services":{"web":{"target":{"type":"compose","file":"compose.yml","service":"web","port":3000}}}}`, true},
		{"compose outside project", `{"services":{"web":{"target":{"type":"compose","project":"shop","file":"../compose.yml","service":"web","port":3000}}}}`, false},
		{"compose absolute", `{"services":{"web":{"target":{"type":"compose","project":"shop","file":"/compose.yml","service":"web","port":3000}}}}`, false},
		{"compose foreign field", `{"services":{"web":{"target":{"type":"compose","project":"shop","file":"compose.yml","service":"web","port":3000,"container":"web"}}}}`, false},
		{"docker option", `{"services":{"web":{"target":{"type":"docker","container":"--all","port":3000}}}}`, false},
		{"docker filter", `{"services":{"web":{"target":{"type":"docker","container":"name=web","port":3000}}}}`, false},
		{"docker slash", `{"services":{"web":{"target":{"type":"docker","container":"/web","port":3000}}}}`, false},
		{"docker foreign field", `{"services":{"web":{"target":{"type":"docker","container":"web","port":3000,"file":"compose.yml"}}}}`, false},
		{"zero port", `{"services":{"db":{"protocol":"tcp","target":{"type":"docker","container":"db","port":0}}}}`, false},
		{"large port", `{"services":{"db":{"protocol":"tcp","target":{"type":"docker","container":"db","port":65536}}}}`, false},
		{"TCP app", `{"services":{"db":{"protocol":"tcp","target":{"type":"app"}}}}`, false},
		{"TCP HTTP", `{"services":{"db":{"protocol":"tcp","target":{"type":"address","address":5432},"http":{"open":false}}}}`, false},
		{"HTTP TCP limits", `{"services":{"web":{"public_url":{"limits":{"tcp":{"total":1}}}}}}`, false},
		{"TLS plain HTTP", `{"services":{"web":{"target":{"type":"address","address":3000,"tls":{}}}}}`, false},
		{"TLS invalid name", `{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":5432},"tls":{"hostname":"db/path","ca":"system"}}}}`, false},
		{"removed publisher port", `{"publisher_group":{"type":"compose","service":"publisher","port":8765}}`, false},
		{"removed publisher root", `{"publisher_group":{"type":"compose","service":"publisher","project_root":"/project"}}`, false},
		{"removed publisher descriptors", `{"publisher_group":{"type":"compose","service":"publisher","app_endpoints":{"web":"/run/web.json"}}}`, false},
		{"host descriptor", `{"publisher_group":{"type":"host","app_endpoints":{"web":"/run/web.json"}}}`, false},
		{"host empty foreign field", `{"publisher_group":{"type":"host","port":0}}`, false},
		{"null target", `{"services":{"web":{"target":null}}}`, false},
		{"null variant field", `{"services":{"web":{"target":{"type":"app","address":null}}}}`, false},
		{"numeric Docker identifier", `{"services":{"web":{"target":{"type":"docker","container":123,"port":3000}}}}`, false},
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
	if err != nil || policy.Mode != "summary" || policy.Retention != 24*time.Hour || policy.MaxBytes != 64<<20 {
		t.Fatalf("inspection=%+v: %v", policy, err)
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
