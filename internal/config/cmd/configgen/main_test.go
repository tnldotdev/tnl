package main

import (
	"reflect"
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestSchemaSourceIncludesServicesTeamAndEphemeral(t *testing.T) {
	reflector := &jsonschema.Reflector{
		Anonymous: true, ExpandedStruct: true, RequiredFromJSONSchemaTags: true,
		Mapper: schemaForType,
	}
	schema := reflector.Reflect(config.Document{})
	tnl := schema.Definitions["TNL"]
	if tnl == nil {
		t.Fatal("TNL definition is missing")
	}
	for _, property := range []string{"team", "services"} {
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
	tunnel := schemaForType(reflect.TypeOf(config.Tunnel{}))
	if _, found := tunnel.Properties.Get("ephemeral"); !found {
		t.Fatal("tunnel ephemeral property is missing")
	}
	if limit, found := tunnel.Properties.Get("request_limit"); !found || limit.Minimum != "1" || limit.Default != 500 {
		t.Fatalf("tunnel request limit schema = %#v", limit)
	}
	keys := map[string]string{}
	collectTypeScriptKeys(reflect.TypeOf(config.TNL{}), keys)
	if keys["allow_ip"] != "allowIP" || keys["startup_timeout"] != "startupTimeout" || keys["request_limit"] != "requestLimit" {
		t.Fatalf("TypeScript key mappings = %#v", keys)
	}
	duration := schemaForType(reflect.TypeOf(config.Duration(0)))
	if duration.Pattern != config.DurationPattern {
		t.Fatalf("duration pattern = %q", duration.Pattern)
	}
}
