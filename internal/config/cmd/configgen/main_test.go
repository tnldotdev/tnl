package main

import (
	"reflect"
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
	serviceSchema := services.AdditionalProperties
	if _, found := serviceSchema.Properties.Get("directory"); !found {
		t.Fatal("service directory property is missing")
	}
	if paths, found := serviceSchema.Properties.Get("paths"); !found || paths.AdditionalProperties == nil || len(paths.AdditionalProperties.OneOf) != 2 {
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
	if limit, found := tunnel.Properties.Get("request_limit"); !found || limit.Minimum != "1" || limit.Default != 500 {
		t.Fatalf("tunnel request limit schema = %#v", limit)
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
	if keys["allow_ip"] != "allowIP" || keys["source_ips"] != "sourceIPs" || keys["startup_timeout"] != "startupTimeout" || keys["request_limit"] != "requestLimit" || keys["request_inspection"] != "requestInspection" || keys["strip_prefix"] != "stripPrefix" {
		t.Fatalf("TypeScript key mappings = %#v", keys)
	}
	duration := schemaForType(reflect.TypeOf(config.Duration(0)))
	if duration.Pattern != config.DurationPattern {
		t.Fatalf("duration pattern = %q", duration.Pattern)
	}
}
