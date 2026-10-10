package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/internal/webhookips"
)

func main() {
	root, err := repositoryRoot()
	if err != nil {
		fatal(err)
	}
	reflector := &jsonschema.Reflector{
		Anonymous: true, ExpandedStruct: true, RequiredFromJSONSchemaTags: true,
		Mapper: schemaForType,
	}
	schema := reflector.Reflect(config.Document{})
	schema.Version = "https://json-schema.org/draft/2020-12/schema"
	schema.ID = "https://tnl.dev/schema/v1.json"
	if property, ok := schema.Properties.Get("version"); ok {
		property.Const = config.DocumentVersion
		property.Description = "Configuration format version."
	}
	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := writeFile(filepath.Join(root, "schema", "v1.json"), append(data, '\n')); err != nil {
		fatal(err)
	}
	keys := make(map[string]string)
	collectTypeScriptKeys(reflect.TypeOf(config.TNL{}), keys)
	data, err = json.MarshalIndent(keys, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := writeFile(filepath.Join(root, "internal", "projectconfig", "keys.gen.json"), append(data, '\n')); err != nil {
		fatal(err)
	}
}

func repositoryRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", errors.New("repository root not found")
		}
		directory = parent
	}
}

func schemaForType(valueType reflect.Type) *jsonschema.Schema {
	switch valueType {
	case reflect.TypeOf(config.Target("")):
		return &jsonschema.Schema{OneOf: []*jsonschema.Schema{
			{Type: "string", MinLength: integerPointer(1)},
			{Type: "integer", Minimum: "1", Maximum: "65535"},
		}}
	case reflect.TypeOf(config.Duration(0)):
		return &jsonschema.Schema{Type: "string", Pattern: config.DurationPattern}
	case reflect.TypeOf(config.Tunnel{}):
		return tunnelSchema()
	case reflect.TypeOf(config.Services{}):
		return servicesSchema()
	case reflect.TypeOf(config.Webhook{}):
		return webhookSchema()
	case reflect.TypeOf(config.Alias{}):
		return aliasSchema()
	case reflect.TypeOf(map[string]config.Alias{}):
		return &jsonschema.Schema{Type: "object", MaxProperties: integerPointer(32),
			PropertyNames: &jsonschema.Schema{Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`}, AdditionalProperties: aliasSchema()}
	case reflect.TypeOf(map[string]config.Webhook{}):
		return &jsonschema.Schema{
			Type: "object", MaxProperties: integerPointer(32),
			PropertyNames:        &jsonschema.Schema{Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`},
			AdditionalProperties: webhookSchema(),
		}
	case reflect.TypeOf(config.TNLDSection{}):
		return tnldSchema()
	default:
		return nil
	}
}

func servicesSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set("directory", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1), Description: "Service directory relative to the project configuration."})
	properties.Set("request_inspection", &jsonschema.Schema{Type: "string", Enum: []any{"summary", "detailed"}, Description: "Local HTTP request capture for this service."})
	tunnel := tunnelSchema()
	tunnel.Description = "PublicURL and tunnel overrides for this service."
	properties.Set("tunnel", tunnel)
	properties.Set("publish", &jsonschema.Schema{Ref: "#/$defs/Publish"})
	properties.Set("readiness", &jsonschema.Schema{Ref: "#/$defs/Readiness"})
	mountProperties := jsonschema.NewProperties()
	mountProperties.Set("service", &jsonschema.Schema{Type: "string", Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`})
	mountProperties.Set("strip_prefix", &jsonschema.Schema{Type: "boolean"})
	properties.Set("paths", &jsonschema.Schema{
		Type: "object", MaxProperties: integerPointer(32),
		AdditionalProperties: &jsonschema.Schema{OneOf: []*jsonschema.Schema{
			{Type: "string", Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`},
			{Type: "object", Required: []string{"service"}, Properties: mountProperties, AdditionalProperties: jsonschema.FalseSchema},
		}},
		Description: "Mount another configured service at a path on this service's public URL.",
	})
	service := &jsonschema.Schema{
		Type: "object", Properties: properties, AdditionalProperties: jsonschema.FalseSchema,
	}
	return &jsonschema.Schema{
		Type: "object", MaxProperties: integerPointer(32),
		PropertyNames:        &jsonschema.Schema{Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`},
		AdditionalProperties: service,
	}
}

func tunnelSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set("domain", &jsonschema.Schema{Type: "string", Description: "Ready team domain used for generated public URL hostnames."})
	properties.Set("name", &jsonschema.Schema{Type: "string", Description: "One DNS label beneath the member namespace."})
	properties.Set("public_url", &jsonschema.Schema{Type: "string", Description: "Exact public URL hostname or HTTPS origin to publish."})
	properties.Set("open", &jsonschema.Schema{Type: "boolean", Description: "Open the public URL in a browser once ready."})
	properties.Set("allow_ip", &jsonschema.Schema{
		Type: "array", Items: &jsonschema.Schema{Type: "string"}, UniqueItems: true,
		Description: "Visitor IP addresses or prefixes allowed to use the public URL; the current client IP is added automatically.",
	})
	properties.Set("allow_all_ips", &jsonschema.Schema{Type: "boolean", Description: "Allow visitors from every IP address."})
	properties.Set("ephemeral", &jsonschema.Schema{Type: "boolean", Description: "Remove the public URL when this tunnel stops."})
	limitProperties := jsonschema.NewProperties()
	limitProperties.Set("requests", &jsonschema.Schema{Type: "integer", Minimum: "1", Description: "Total admitted application requests for this tunnel."})
	rateProperties := jsonschema.NewProperties()
	rateProperties.Set("requests", &jsonschema.Schema{Type: "integer", Minimum: "1"})
	rateProperties.Set("per", &jsonschema.Schema{Type: "string", Pattern: config.DurationPattern})
	limitProperties.Set("rate", &jsonschema.Schema{Type: "object", Required: []string{"requests", "per"}, Properties: rateProperties, AdditionalProperties: jsonschema.FalseSchema})
	limitProperties.Set("concurrency", &jsonschema.Schema{Type: "integer", Minimum: "1", Default: 500, Description: "Maximum simultaneous application requests, streams, and upgrades."})
	properties.Set("limits", &jsonschema.Schema{Type: "object", Properties: limitProperties, AdditionalProperties: jsonschema.FalseSchema})
	allowAllProperties := jsonschema.NewProperties()
	allowAllProperties.Set("allow_all_ips", &jsonschema.Schema{Const: true})
	return &jsonschema.Schema{
		Type: "object", Properties: properties, AdditionalProperties: jsonschema.FalseSchema,
		AllOf: []*jsonschema.Schema{
			{Not: &jsonschema.Schema{Required: []string{"name", "public_url"}}},
			{
				If: &jsonschema.Schema{Properties: allowAllProperties, Required: []string{"allow_all_ips"}},
				Then: &jsonschema.Schema{Not: &jsonschema.Schema{AnyOf: []*jsonschema.Schema{
					{Required: []string{"allow_ip"}},
				}}},
			},
		},
	}
}

func webhookSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set("service", &jsonschema.Schema{Type: "string"})
	properties.Set("path", &jsonschema.Schema{Type: "string", Pattern: `^/[a-zA-Z0-9._~-]+(/[a-zA-Z0-9._~-]+)*$`})
	properties.Set("delivery", &jsonschema.Schema{Type: "string", Enum: []any{"fanout", "selected"}})
	properties.Set("methods", &jsonschema.Schema{Type: "array", MinItems: integerPointer(1), Items: &jsonschema.Schema{Type: "string", Enum: []any{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}}, UniqueItems: true})
	providerValues := make([]any, 0, len(webhookips.Names()))
	for _, name := range webhookips.Names() {
		providerValues = append(providerValues, name)
	}
	properties.Set("provider", &jsonschema.Schema{Type: "string", Enum: providerValues})
	properties.Set("source_ips", &jsonschema.Schema{Type: "array", MinItems: integerPointer(1), Items: &jsonschema.Schema{Type: "string"}, UniqueItems: true})
	return &jsonschema.Schema{Type: "object", Required: []string{"path", "service", "provider"}, Properties: properties, AdditionalProperties: jsonschema.FalseSchema}
}

func aliasSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set("service", &jsonschema.Schema{Type: "string", Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`, Description: "Configured entry service serving the alias."})
	properties.Set("name", &jsonschema.Schema{Type: "string", Pattern: `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`, MinLength: integerPointer(1), MaxLength: integerPointer(253), Description: "Relative DNS name beneath the member namespace; defaults to the alias key. Nested names require server permission."})
	properties.Set("domain", &jsonschema.Schema{Type: "string", Description: "Ready team domain; otherwise inherit the entry service's domain."})
	properties.Set("public_url", &jsonschema.Schema{Type: "string", Description: "Exact authorized public URL hostname or HTTPS origin; mutually exclusive with name and domain."})
	tunnel := tunnelSchema()
	for _, name := range []string{"allow_ip", "allow_all_ips"} {
		value, _ := tunnel.Properties.Get(name)
		properties.Set(name, value)
	}
	return &jsonschema.Schema{Type: "object", Required: []string{"service"}, Properties: properties, AdditionalProperties: jsonschema.FalseSchema,
		AllOf: []*jsonschema.Schema{
			{Not: &jsonschema.Schema{Required: []string{"name", "public_url"}}},
			{Not: &jsonschema.Schema{Required: []string{"domain", "public_url"}}},
			tunnel.AllOf[1],
		}}
}

func tnldSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	typeOfConfig := reflect.TypeOf(tnldconfig.Config{})
	durationType := reflect.TypeOf(time.Duration(0))
	for index := 0; index < typeOfConfig.NumField(); index++ {
		field := typeOfConfig.Field(index)
		name := strings.ReplaceAll(field.Tag.Get("name"), "-", "_")
		if name == "" || name == "database_direct_url" {
			continue
		}
		fieldSchema := primitiveSchema(field.Type, field.Type == durationType)
		fieldSchema.Description = field.Tag.Get("help")
		if values := strings.Split(field.Tag.Get("enum"), ","); len(values) > 1 {
			fieldSchema.Enum = make([]any, len(values))
			for index, value := range values {
				fieldSchema.Enum[index] = value
			}
		}
		if value := field.Tag.Get("default"); value != "" {
			fieldSchema.Default = defaultValue(value, field.Type, field.Type == durationType)
		}
		properties.Set(name, fieldSchema)
	}
	return &jsonschema.Schema{Type: "object", Properties: properties, AdditionalProperties: jsonschema.FalseSchema}
}

func primitiveSchema(valueType reflect.Type, duration bool) *jsonschema.Schema {
	if duration {
		return &jsonschema.Schema{Type: "string"}
	}
	switch valueType.Kind() {
	case reflect.String:
		return &jsonschema.Schema{Type: "string"}
	case reflect.Bool:
		return &jsonschema.Schema{Type: "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return &jsonschema.Schema{Type: "integer"}
	case reflect.Float64:
		return &jsonschema.Schema{Type: "number"}
	case reflect.Slice:
		return &jsonschema.Schema{Type: "array", Items: primitiveSchema(valueType.Elem(), false)}
	default:
		panic(fmt.Sprintf("unsupported tnld config field type %s", valueType))
	}
}

func defaultValue(value string, valueType reflect.Type, duration bool) any {
	if duration {
		return value
	}
	switch valueType.Kind() {
	case reflect.Bool:
		parsed, _ := strconv.ParseBool(value)
		return parsed
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		parsed, _ := strconv.ParseInt(value, 10, 64)
		return parsed
	case reflect.Float64:
		parsed, _ := strconv.ParseFloat(value, 64)
		return parsed
	default:
		return value
	}
}

func collectTypeScriptKeys(valueType reflect.Type, result map[string]string) {
	mappings := projectconfig.TypeScriptKeyMappings()
	for index := 0; index < valueType.NumField(); index++ {
		field := valueType.Field(index)
		staticName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if staticName == "" || staticName == "-" {
			continue
		}
		typeScriptName := mappings[staticName]
		if typeScriptName == "" {
			typeScriptName = staticName
		}
		if typeScriptName != staticName {
			result[staticName] = typeScriptName
		}
		fieldType := field.Type
		if fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		if fieldType.Kind() == reflect.Struct && fieldType != reflect.TypeOf(config.Target("")) && fieldType != reflect.TypeOf(config.Duration(0)) {
			collectTypeScriptKeys(fieldType, result)
		} else if fieldType.Kind() == reflect.Map {
			elementType := fieldType.Elem()
			if elementType.Kind() == reflect.Pointer {
				elementType = elementType.Elem()
			}
			if elementType.Kind() == reflect.Struct {
				collectTypeScriptKeys(elementType, result)
			}
		}
	}
}

func integerPointer(value uint64) *uint64 { return &value }

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
