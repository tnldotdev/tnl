package main

import (
	"reflect"
	"regexp"
	"slices"
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestSchemaSourceScopesServerAndTeamToProject(t *testing.T) {
	reflector := &jsonschema.Reflector{
		Anonymous: true, ExpandedStruct: true, RequiredFromJSONSchemaTags: true,
		Mapper: schemaForType,
	}
	schema := reflector.Reflect(config.Document{})
	tnl := schema.Definitions["TNL"]
	if tnl == nil {
		t.Fatal("TNL definition is missing")
	}
	for _, property := range []string{"server", "team", "services"} {
		if _, found := tnl.Properties.Get(property); !found {
			t.Fatalf("TNL property %q is missing", property)
		}
	}
	services := schemaForType(reflect.TypeOf(config.Services{}))
	if services.MaxProperties == nil || *services.MaxProperties != 32 || services.PropertyNames == nil ||
		services.PropertyNames.Pattern == "" || services.AdditionalProperties == nil {
		t.Fatalf("services schema = %#v", services)
	}
	serviceSchema := services.AdditionalProperties.OneOf[0]
	if _, found := serviceSchema.Properties.Get("directory"); found {
		t.Fatal("removed service directory is still exposed")
	}
	http, _ := serviceSchema.Properties.Get("http")
	if paths, found := http.Properties.Get("paths"); !found || paths.AdditionalProperties == nil || len(paths.AdditionalProperties.OneOf) != 2 {
		t.Fatalf("service path mount schema = %#v", paths)
	}
	for _, property := range []string{"server", "team"} {
		if _, found := serviceSchema.Properties.Get(property); found {
			t.Fatalf("service %s property must be project-wide", property)
		}
	}
	tunnel := schemaForType(reflect.TypeOf(config.Tunnel{}))
	if _, found := tunnel.Properties.Get("ephemeral"); !found {
		t.Fatal("tunnel ephemeral property is missing")
	}
	if limits, found := tunnel.Properties.Get("limits"); !found || limits.Properties == nil {
		t.Fatalf("tunnel limits schema = %#v", limits)
	} else if http, found := limits.Properties.Get("http"); !found || http.Properties == nil {
		t.Fatal("HTTP limits are missing")
	} else if concurrency, found := http.Properties.Get("concurrency"); !found || concurrency.Minimum != "1" || concurrency.Maximum != "9007199254740991" {
		t.Fatalf("tunnel concurrency schema = %#v", concurrency)
	}
	if _, found := tunnel.Properties.Get("allow_providers"); found {
		t.Fatal("tunnel-wide provider grants must not be generated")
	}
	webhook := schemaForType(reflect.TypeOf(config.Webhook{}))
	if provider, found := webhook.Properties.Get("provider"); !found || len(provider.Enum) != 23 || provider.Enum[0] != "amazon-sns" {
		t.Fatalf("webhook provider schema = %#v", provider)
	}
	if ips, found := webhook.Properties.Get("source_ips"); !found || ips.MinItems == nil || *ips.MinItems != 1 {
		t.Fatalf("webhook source override schema = %#v", ips)
	}
	if ips, found := tunnel.Properties.Get("allow_ip"); !found || ips.MaxItems != nil {
		t.Fatalf("tunnel IP limit = %#v", ips)
	}
	keys := map[string]string{}
	collectTypeScriptKeys(reflect.TypeOf(config.TNL{}), keys)
	if keys["allow_ip"] != "allowIP" || keys["source_ips"] != "sourceIPs" || keys["startup_timeout"] != "" || keys["request_limit"] != "" || keys["strip_prefix"] != "stripPrefix" {
		t.Fatalf("TypeScript key mappings = %#v", keys)
	}
	duration := schemaForType(reflect.TypeOf(config.Duration(0)))
	if duration.Pattern != config.DurationPattern {
		t.Fatalf("duration pattern = %q", duration.Pattern)
	}
}

func TestSchemaHasDisjointTargetsAndNoRetiredPublicFields(t *testing.T) {
	reflector := &jsonschema.Reflector{Anonymous: true, ExpandedStruct: true, RequiredFromJSONSchemaTags: true, Mapper: schemaForType}
	schema := reflector.Reflect(config.Document{})
	for _, key := range []string{"publish", "readiness"} {
		if _, found := schema.Definitions["TNL"].Properties.Get(key); found {
			t.Fatalf("retired root %s is generated", key)
		}
	}
	service := servicesSchema().AdditionalProperties.OneOf[0]
	for _, key := range []string{"publish", "readiness", "paths", "directory"} {
		if _, found := service.Properties.Get(key); found {
			t.Fatalf("retired service %s is generated", key)
		}
	}
	target, _ := service.Properties.Get("target")
	if len(target.OneOf) != 4 {
		t.Fatal("target variants are not disjoint")
	}
	for _, variant := range target.OneOf {
		kind, _ := variant.Properties.Get("type")
		if kind.Const == "compose" && (slices.Contains(variant.Required, "project") || slices.Contains(variant.Required, "file") || !slices.Contains(variant.Required, "service") || !slices.Contains(variant.Required, "port")) {
			t.Fatalf("Compose target required fields = %v", variant.Required)
		}
		if kind.Const == "app" {
			for _, field := range []string{"address", "project", "file", "service", "port", "container", "tls"} {
				if value, found := variant.Properties.Get(field); !found || value != jsonschema.FalseSchema {
					t.Fatalf("app target permits %s", field)
				}
			}
		}
		if kind.Const == "compose" || kind.Const == "docker" {
			port, found := variant.Properties.Get("port")
			if !found || port.Minimum != "1" || port.Maximum != "65535" {
				t.Fatal("private port bounds missing")
			}
		}
	}
	if _, found := tunnelSchema().Properties.Get("open"); found {
		t.Fatal("browser opening is still a tunnel field")
	}
	limits, _ := tunnelSchema().Properties.Get("limits")
	for _, key := range []string{"http", "tcp", "traffic"} {
		if _, found := limits.Properties.Get(key); !found {
			t.Fatalf("missing %s limits", key)
		}
	}
	traffic, _ := limits.Properties.Get("traffic")
	for _, key := range []string{"connections", "rate", "rate_per", "burst", "upload_bytes", "download_bytes", "total_connections", "total_upload_bytes", "total_download_bytes"} {
		if _, found := traffic.Properties.Get(key); !found {
			t.Fatalf("traffic field %s is missing", key)
		}
	}
	for _, key := range []string{"total_bytes", "burst_bytes"} {
		if _, found := traffic.Properties.Get(key); found {
			t.Fatalf("combined traffic field %s is exposed", key)
		}
	}
	pattern := regexp.MustCompile(schemaForType(reflect.TypeOf(config.ByteSize(0))).Pattern)
	for _, size := range []string{"1MiB", "1024KiB", "1024MiB", "1048576KiB", "1GiB"} {
		if !pattern.MatchString(size) {
			t.Fatalf("schema rejected %s", size)
		}
	}
	for _, size := range []string{"1023KiB", "1048577KiB", "1025MiB", "2GiB", "1MB", "+1MiB", "1.5MiB"} {
		if pattern.MatchString(size) {
			t.Fatalf("schema accepted %s", size)
		}
	}
}

func TestProtocolDiscriminatedServiceAndPublisherSchemas(t *testing.T) {
	variants := servicesSchema().AdditionalProperties.OneOf
	if len(variants) != 2 {
		t.Fatal("services must have HTTP and TCP union members")
	}
	for i, service := range variants {
		protocol, _ := service.Properties.Get("protocol")
		target, _ := service.Properties.Get("target")
		http, _ := service.Properties.Get("http")
		if i == 0 {
			if !reflect.DeepEqual(protocol.Enum, []any{"http"}) || slices.Contains(service.Required, "protocol") || len(target.OneOf) != 4 || http == jsonschema.FalseSchema {
				t.Fatal("HTTP service lost inference or HTTP settings")
			}
		} else {
			if !reflect.DeepEqual(protocol.Enum, []any{"tcp", "ssh"}) || !slices.Contains(service.Required, "protocol") || !slices.Contains(service.Required, "target") || len(target.OneOf) != 3 || http != jsonschema.FalseSchema {
				t.Fatal("TCP service does not require its protocol and non-app target or forbids no HTTP settings")
			}
		}
		for _, variant := range target.OneOf {
			kind, _ := variant.Properties.Get("type")
			if i == 1 && kind.Const == "app" {
				t.Fatal("TCP service accepts an app target")
			}
			if kind.Const != "app" {
				tls, _ := variant.Properties.Get("tls")
				mode, _ := tls.Properties.Get("mode")
				want := []any{"direct"}
				if i == 1 {
					want = []any{"direct", "postgres", "mysql"}
				}
				if !slices.Contains(tls.Required, "mode") || !reflect.DeepEqual(mode.Enum, want) {
					t.Fatalf("%s target TLS modes = %v", kind.Const, mode.Enum)
				}
			}
			for _, field := range []string{"address", "project", "file", "service", "port", "container", "tls"} {
				value, found := variant.Properties.Get(field)
				if !found {
					t.Fatalf("%s target needs an explicit allowed or forbidden %s field", kind.Const, field)
				}
				if field == "container" && kind.Const != "docker" && value != jsonschema.FalseSchema {
					t.Fatal("non-Docker target permits container")
				}
				if field == "address" && kind.Const != "address" && value != jsonschema.FalseSchema {
					t.Fatal("non-address target permits address")
				}
			}
		}
	}
	compose := publisherSchema().OneOf[1]
	if !reflect.DeepEqual(compose.Required, []string{"type", "service"}) {
		t.Fatalf("Compose publisher required fields = %v", compose.Required)
	}
	for _, field := range []string{"port", "project_root", "app_endpoints"} {
		if _, found := compose.Properties.Get(field); found {
			t.Fatalf("removed publisher field %s is exposed", field)
		}
	}
}
