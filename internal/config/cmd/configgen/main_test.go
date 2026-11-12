package main

import (
	"reflect"
	"regexp"
	"slices"
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestSchemaInventoryAndCloudSelectorBounds(t *testing.T) {
	ports, ok := tnldSchema().Properties.Get("service_port_ranges")
	if !ok || ports.MinItems == nil || *ports.MinItems != 1 || ports.MaxItems == nil || *ports.MaxItems != tcpport.MaxInventoryDeclarations || !reflect.DeepEqual(ports.Default, []string{"20000-20015"}) {
		t.Fatal("inventory metadata", ports)
	}
	for _, protocol := range []string{"postgres", "mysql", "kubernetes"} {
		for _, variant := range targetSchema(protocol).OneOf {
			kind, _ := variant.Properties.Get("type")
			if kind.Const != "eks" && kind.Const != "rds" {
				continue
			}
			region, _ := variant.Properties.Get("region")
			if region.Pattern != config.AWSRegionPattern || region.MaxLength == nil || *region.MaxLength != 32 {
				t.Fatal("cloud region metadata", region)
			}
			name, _ := variant.Properties.Get("cluster")
			if kind.Const == "rds" && name != jsonschema.FalseSchema && (name.Pattern != config.RDSNamePattern || name.Not == nil) {
				t.Fatal("RDS name metadata", name)
			}
		}
	}
}

func TestSchemaSeparatesLogicalServicesFromEnvironmentAuthority(t *testing.T) {
	reflector := &jsonschema.Reflector{Anonymous: true, ExpandedStruct: true, RequiredFromJSONSchemaTags: true, Mapper: schemaForType}
	schema := reflector.Reflect(config.Document{})
	tnl := schema.Definitions["TNL"]
	for _, key := range []string{"server", "team", "services", "environments", "collections"} {
		if _, found := tnl.Properties.Get(key); !found {
			t.Fatalf("missing root %s", key)
		}
	}
	for _, key := range []string{"workloads", "publisher_groups", "publish", "readiness"} {
		if _, found := tnl.Properties.Get(key); found {
			t.Fatalf("retired root %s", key)
		}
	}
	services := servicesSchema()
	if *services.MaxProperties != 32 || services.PropertyNames == nil || services.PropertyNames.Pattern == "" {
		t.Fatal("service name bounds missing")
	}
	service := services.AdditionalProperties
	protocol, _ := service.Properties.Get("protocol")
	if !reflect.DeepEqual(protocol.Enum, []any{"http", "tcp", "mysql", "postgres", "kubernetes"}) {
		t.Fatal("service protocols changed")
	}
	for _, key := range []string{"target", "target_binding", "publisher_group", "public_url", "name", "access", "inspection", "http", "tls"} {
		if value, found := service.Properties.Get(key); !found || value != jsonschema.FalseSchema {
			t.Fatalf("definition permits %s", key)
		}
	}
	for _, key := range []string{"server", "team", "directory", "readiness", "paths", "publish"} {
		if _, found := service.Properties.Get(key); found {
			t.Fatalf("service contains %s", key)
		}
	}
	collection := schema.Definitions["Collection"]
	if collection == nil || collection.Properties != nil && collection.Properties.Len() != 0 || collection.AdditionalProperties != jsonschema.FalseSchema {
		t.Fatal("collection contains a second schema or template")
	}
	keys := map[string]string{}
	collectTypeScriptKeys(reflect.TypeOf(config.TNL{}), keys)
	for key, want := range map[string]string{"source_ips": "sourceIPs", "strip_prefix": "stripPrefix", "require_post_quantum": "requirePostQuantum", "ca_pem": "caPEM"} {
		if keys[key] != want {
			t.Fatalf("key %s=%s, want %s", key, keys[key], want)
		}
	}
	for _, key := range []string{"target_binding", "publisher_group", "publisher_groups", "request_limit", "allow_ip", "startup_timeout"} {
		if keys[key] != "" {
			t.Fatalf("retired key mapping %s", key)
		}
	}
}

func TestEnvironmentTargetsAndLocalHTTPHaveSeparateBoundaries(t *testing.T) {
	environments := schemaForType(reflect.TypeOf(map[string]config.Environment{}))
	if environments.AdditionalProperties == nil || len(environments.AdditionalProperties.AnyOf) != 0 {
		t.Fatal("file schema permits local-only settings in remote environments")
	}
	for _, local := range []bool{false, true} {
		environment := environmentSchema(local)
		if _, found := environment.Properties.Get("server"); !found {
			t.Fatal("per-environment server missing")
		}
		for _, target := range environmentTargetSchema(local).OneOf {
			address, _ := target.Properties.Get("address")
			discovery, _ := target.Properties.Get("discovery")
			if address != jsonschema.FalseSchema && discovery != jsonschema.FalseSchema {
				t.Fatal("mixed destination authority")
			}
			if !local && !slices.Contains(target.Required, "address") && !slices.Contains(target.Required, "discovery") {
				t.Fatal("remote target may omit its destination")
			}
			for _, key := range []string{"name", "access", "inspection", "public_url"} {
				value, _ := target.Properties.Get(key)
				if local == (value == jsonschema.FalseSchema) {
					t.Fatalf("local-only field %s boundary", key)
				}
			}
		}
	}
	local := environmentTargetSchema(true).OneOf[0]
	http, _ := local.Properties.Get("http")
	paths, _ := http.Properties.Get("paths")
	if paths == nil || len(paths.AdditionalProperties.OneOf) != 2 || *paths.MaxProperties != 32 {
		t.Fatal("path mount forms or bounds missing")
	}
	for _, key := range []string{"readiness", "open"} {
		if _, found := http.Properties.Get(key); !found {
			t.Fatalf("local HTTP lost %s", key)
		}
	}
}

func TestDiscoverySchemaRetainsProtocolAndExactVariantChecks(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "mysql", "postgres", "kubernetes"} {
		for _, target := range targetSchema(protocol).OneOf {
			kind, _ := target.Properties.Get("type")
			if protocol != "http" && kind.Const == "app" || kind.Const == "eks" && protocol != "kubernetes" || kind.Const == "rds" && protocol != "postgres" && protocol != "mysql" {
				t.Fatal("discovery protocol boundary changed")
			}
			if kind.Const == "compose" && (slices.Contains(target.Required, "project") || slices.Contains(target.Required, "file") || !slices.Contains(target.Required, "service") || !slices.Contains(target.Required, "port")) {
				t.Fatal("Compose defaults or required fields changed")
			}
			if kind.Const == "docker" || kind.Const == "compose" {
				port, _ := target.Properties.Get("port")
				if port.Minimum != "1" || port.Maximum != "65535" {
					t.Fatal("discovery port bounds missing")
				}
			}
			for _, field := range []string{"address", "project", "file", "service", "port", "container", "tls", "region", "cluster", "instance", "endpoint"} {
				if _, found := target.Properties.Get(field); !found {
					t.Fatalf("target needs explicit allowed/forbidden %s", field)
				}
			}
			tls, _ := target.Properties.Get("tls")
			if kind.Const == "eks" || kind.Const == "rds" {
				if tls != jsonschema.FalseSchema {
					t.Fatal("provider discovery must supply trust")
				}
				continue
			}
			if tls.AdditionalProperties != jsonschema.FalseSchema {
				t.Fatal("TLS fields are not exact")
			}
			if _, found := tls.Properties.Get("mode"); found {
				t.Fatal("TLS negotiation must follow protocol")
			}
		}
	}
}

func TestPublicURLPolicyAndInspectionSchemaBounds(t *testing.T) {
	tunnel := tunnelSchema()
	if _, found := tunnel.Properties.Get("ephemeral"); !found {
		t.Fatal("ephemeral missing")
	}
	for _, field := range []string{"open", "allow_providers"} {
		if _, found := tunnel.Properties.Get(field); found {
			t.Fatalf("retired tunnel %s", field)
		}
	}
	access, _ := tunnel.Properties.Get("access")
	if len(access.OneOf) != 2 {
		t.Fatal("access shorthand/object forms missing")
	}
	limits, _ := tunnel.Properties.Get("limits")
	for _, key := range []string{"http", "tcp", "traffic"} {
		if _, found := limits.Properties.Get(key); !found {
			t.Fatalf("missing %s limits", key)
		}
	}
	http, _ := limits.Properties.Get("http")
	concurrency, _ := http.Properties.Get("concurrency")
	if concurrency.Minimum != "1" || concurrency.Maximum != "9007199254740991" {
		t.Fatal("safe integer bounds missing")
	}
	traffic, _ := limits.Properties.Get("traffic")
	for _, key := range []string{"connections", "rate", "rate_per", "burst", "upload_bytes", "download_bytes", "total_connections", "total_upload_bytes", "total_download_bytes"} {
		if _, found := traffic.Properties.Get(key); !found {
			t.Fatalf("traffic field %s missing", key)
		}
	}
	for _, key := range []string{"total_bytes", "burst_bytes"} {
		if _, found := traffic.Properties.Get(key); found {
			t.Fatalf("combined traffic field %s", key)
		}
	}
	if schemaForType(reflect.TypeOf(config.Duration(0))).Pattern != config.DurationPattern {
		t.Fatal("duration syntax drift")
	}
	pattern := regexp.MustCompile(schemaForType(reflect.TypeOf(config.ByteSize(0))).Pattern)
	for _, size := range []string{"1MiB", "1024KiB", "1024MiB", "1048576KiB", "1GiB"} {
		if !pattern.MatchString(size) {
			t.Fatalf("rejected %s", size)
		}
	}
	for _, size := range []string{"1023KiB", "1048577KiB", "1025MiB", "2GiB", "1MB", "+1MiB", "1.5MiB"} {
		if pattern.MatchString(size) {
			t.Fatalf("accepted %s", size)
		}
	}
	webhook := webhookSchema()
	provider, _ := webhook.Properties.Get("provider")
	if len(provider.Enum) != 23 || provider.Enum[0] != "amazon-sns" {
		t.Fatal("provider catalog drift")
	}
	ips, _ := webhook.Properties.Get("source_ips")
	if ips.MinItems == nil || *ips.MinItems != 1 {
		t.Fatal("empty source override permitted")
	}
}
