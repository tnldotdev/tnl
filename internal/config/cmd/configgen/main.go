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
	case reflect.TypeOf(config.ByteSize(0)):
		return &jsonschema.Schema{Type: "string", Pattern: `^(102[4-9]|10[3-9][0-9]|1[1-9][0-9]{2}|[2-9][0-9]{3}|[1-9][0-9]{4,5}|10[0-3][0-9]{4}|104[0-7][0-9]{3}|1048[0-4][0-9]{2}|10485[0-6][0-9]|104857[0-6])KiB$|^([1-9]|[1-9][0-9]|[1-9][0-9]{2}|10[01][0-9]|102[0-4])MiB$|^1GiB$`}
	case reflect.TypeOf(config.AppPublisher{}):
		return publisherSchema()
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
	return &jsonschema.Schema{
		Type: "object", MaxProperties: integerPointer(32),
		PropertyNames: &jsonschema.Schema{Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`},
		AdditionalProperties: &jsonschema.Schema{OneOf: []*jsonschema.Schema{
			serviceSchema("http"), serviceSchema("tcp"), serviceSchema("ssh"),
		}},
	}
}

// serviceSchema keeps the protocol boundary in the generated TypeScript union,
// where JSON Schema conditionals alone would not constrain the declarations.
func serviceSchema(protocol string) *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set("inspection", &jsonschema.Schema{Ref: "#/$defs/Inspection"})
	tunnel := tunnelSchema()
	tunnel.Description = "PublicURL and tunnel overrides for this service."
	limits, _ := tunnel.Properties.Get("limits")
	otherProtocol := "tcp"
	if protocol != "http" {
		otherProtocol = "http"
	}
	limits.Properties.Set(otherProtocol, jsonschema.FalseSchema)
	if protocol == "tcp" {
		properties.Set("tunnel", jsonschema.FalseSchema)
		private := jsonschema.NewProperties()
		private.Set("name", &jsonschema.Schema{Type: "string", Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`})
		properties.Set("private", &jsonschema.Schema{Type: "object", Properties: private, AdditionalProperties: jsonschema.FalseSchema})
	} else {
		properties.Set("tunnel", tunnel)
		properties.Set("private", jsonschema.FalseSchema)
	}
	protocols := []any{protocol}
	target := targetSchema()
	if protocol != "http" {
		target.OneOf = target.OneOf[1:]
		if protocol == "ssh" {
			for _, variant := range target.OneOf {
				variant.Properties.Set("tls", jsonschema.FalseSchema)
			}
		}
	} else {
		for _, variant := range target.OneOf[1:] {
			tls, _ := variant.Properties.Get("tls")
			mode, _ := tls.Properties.Get("mode")
			mode.Enum = []any{"direct"}
		}
	}
	properties.Set("protocol", &jsonschema.Schema{Type: "string", Enum: protocols})
	properties.Set("target", target)
	httpProperties := jsonschema.NewProperties()
	readiness := jsonschema.NewProperties()
	readiness.Set("path", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1)})
	httpProperties.Set("readiness", &jsonschema.Schema{Type: "object", Properties: readiness, Required: []string{"path"}, AdditionalProperties: jsonschema.FalseSchema})
	httpProperties.Set("open", &jsonschema.Schema{Type: "boolean"})
	mountProperties := jsonschema.NewProperties()
	mountProperties.Set("service", &jsonschema.Schema{Type: "string", Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`})
	mountProperties.Set("strip_prefix", &jsonschema.Schema{Type: "boolean"})
	httpProperties.Set("paths", &jsonschema.Schema{
		Type: "object", MaxProperties: integerPointer(32),
		AdditionalProperties: &jsonschema.Schema{OneOf: []*jsonschema.Schema{
			{Type: "string", Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`},
			{Type: "object", Required: []string{"service"}, Properties: mountProperties, AdditionalProperties: jsonschema.FalseSchema},
		}},
		Description: "Mount another configured service at a path on this service's public URL.",
	})
	properties.Set("http", &jsonschema.Schema{Type: "object", Properties: httpProperties, AdditionalProperties: jsonschema.FalseSchema})
	if protocol != "http" {
		properties.Set("http", jsonschema.FalseSchema)
	}
	service := &jsonschema.Schema{
		Type: "object", Properties: properties, AdditionalProperties: jsonschema.FalseSchema,
	}
	if protocol != "http" {
		service.Required = []string{"protocol", "target"}
	}
	return service
}

func tunnelSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set("domain", &jsonschema.Schema{Type: "string", Description: "Ready team domain used for generated public URL hostnames."})
	properties.Set("name", &jsonschema.Schema{Type: "string", Description: "One DNS label beneath the member namespace."})
	properties.Set("public_url", &jsonschema.Schema{Type: "string", Description: "Exact public URL hostname or HTTPS origin to publish."})
	accessProperties := jsonschema.NewProperties()
	accessProperties.Set("mode", &jsonschema.Schema{Type: "string", Enum: []any{"restricted", "anonymous"}})
	accessProperties.Set("ip", &jsonschema.Schema{Type: "array", MinItems: integerPointer(1), MaxItems: integerPointer(256),
		Items: &jsonschema.Schema{Type: "string"}, UniqueItems: true})
	properties.Set("access", &jsonschema.Schema{OneOf: []*jsonschema.Schema{
		{Type: "string", Enum: []any{"restricted", "anonymous"}},
		{Type: "object", Properties: accessProperties, AdditionalProperties: jsonschema.FalseSchema},
	}})
	properties.Set("ephemeral", &jsonschema.Schema{Type: "boolean", Description: "Remove the public URL when this tunnel stops."})
	limits := jsonschema.NewProperties()
	for _, protocol := range []string{"http", "tcp"} {
		work := jsonschema.NewProperties()
		work.Set("total", positiveInteger())
		work.Set("concurrency", positiveInteger())
		work.Set("rate", rateSchema("count", "burst"))
		limits.Set(protocol, &jsonschema.Schema{Type: "object", Properties: work, AdditionalProperties: jsonschema.FalseSchema})
	}
	traffic := jsonschema.NewProperties()
	for _, field := range []string{"connections", "rate", "burst", "upload_bytes", "download_bytes", "total_connections", "total_upload_bytes", "total_download_bytes"} {
		traffic.Set(field, positiveInteger())
	}
	traffic.Set("rate_per", &jsonschema.Schema{Type: "string", Pattern: config.DurationPattern})
	limits.Set("traffic", &jsonschema.Schema{Type: "object", Properties: traffic, AdditionalProperties: jsonschema.FalseSchema})
	properties.Set("limits", &jsonschema.Schema{Type: "object", Properties: limits, AdditionalProperties: jsonschema.FalseSchema})
	return &jsonschema.Schema{
		Type: "object", Properties: properties, AdditionalProperties: jsonschema.FalseSchema,
		AllOf: []*jsonschema.Schema{{Not: &jsonschema.Schema{Required: []string{"name", "public_url"}}}},
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

func positiveInteger() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "integer", Minimum: "1", Maximum: "9007199254740991"}
}

func rateSchema(count, burst string) *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set(count, positiveInteger())
	properties.Set("per", &jsonschema.Schema{Type: "string", Pattern: config.DurationPattern})
	properties.Set(burst, positiveInteger())
	return &jsonschema.Schema{Type: "object", Properties: properties, AdditionalProperties: jsonschema.FalseSchema}
}

func targetSchema() *jsonschema.Schema {
	variants := []*jsonschema.Schema{}
	for _, kind := range []string{"app", "address", "compose", "docker"} {
		properties := jsonschema.NewProperties()
		properties.Set("type", &jsonschema.Schema{Type: "string", Const: kind})
		required := []string{"type"}
		switch kind {
		case "address":
			properties.Set("address", schemaForType(reflect.TypeOf(config.Target(""))))
			required = append(required, "address")
		case "compose":
			properties.Set("project", &jsonschema.Schema{Type: "string", Pattern: `^[a-z0-9][a-z0-9_-]{0,62}$`})
			properties.Set("file", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1), Pattern: `^(?!/)(?!.*(?:^|[/\\])\.\.(?:[/\\]|$))[^\\\u0000]+$`})
			properties.Set("service", &jsonschema.Schema{Type: "string", Pattern: `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`})
			required = append(required, "service", "port")
		case "docker":
			properties.Set("container", &jsonschema.Schema{Type: "string", Pattern: `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`})
			required = append(required, "container", "port")
		}
		if kind == "compose" || kind == "docker" {
			properties.Set("port", &jsonschema.Schema{Type: "integer", Minimum: "1", Maximum: "65535"})
		}
		if kind != "app" {
			tls := jsonschema.NewProperties()
			tls.Set("mode", &jsonschema.Schema{Type: "string", Enum: []any{"direct", "postgres", "mysql"}})
			tls.Set("server_name", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1), MaxLength: integerPointer(253)})
			tls.Set("ca_file", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1)})
			properties.Set("tls", &jsonschema.Schema{Type: "object", Properties: tls, Required: []string{"mode"}, AdditionalProperties: jsonschema.FalseSchema})
		}
		// explicit forbidden fields also reject structurally inferred mixed targets
		// in defineConfig, rather than relying on fresh-object excess checks.
		for _, field := range []string{"address", "project", "file", "service", "port", "container", "tls"} {
			if _, found := properties.Get(field); !found {
				properties.Set(field, jsonschema.FalseSchema)
			}
		}
		variants = append(variants, &jsonschema.Schema{Type: "object", Properties: properties, Required: required, AdditionalProperties: jsonschema.FalseSchema})
	}
	return &jsonschema.Schema{OneOf: variants}
}

func publisherSchema() *jsonschema.Schema {
	host := jsonschema.NewProperties()
	host.Set("type", &jsonschema.Schema{Type: "string", Const: "host"})
	compose := jsonschema.NewProperties()
	compose.Set("type", &jsonschema.Schema{Type: "string", Const: "compose"})
	compose.Set("service", &jsonschema.Schema{Type: "string", Pattern: `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`})
	compose.Set("file", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1), Pattern: `^(?!/)(?!.*(?:^|[/\\])\.\.(?:[/\\]|$))[^\\\u0000]+$`})
	return &jsonschema.Schema{OneOf: []*jsonschema.Schema{
		{Type: "object", Properties: host, Required: []string{"type"}, AdditionalProperties: jsonschema.FalseSchema},
		{Type: "object", Properties: compose, Required: []string{"type", "service"}, AdditionalProperties: jsonschema.FalseSchema},
	}}
}

func aliasSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set("service", &jsonschema.Schema{Type: "string", Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`, Description: "Configured entry service serving the alias."})
	properties.Set("name", &jsonschema.Schema{Type: "string", Pattern: `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`, MinLength: integerPointer(1), MaxLength: integerPointer(253), Description: "Relative DNS name beneath the member namespace; defaults to the alias key. Nested names require server permission."})
	properties.Set("domain", &jsonschema.Schema{Type: "string", Description: "Ready team domain; otherwise inherit the entry service's domain."})
	properties.Set("public_url", &jsonschema.Schema{Type: "string", Description: "Exact authorized public URL hostname or HTTPS origin; mutually exclusive with name and domain."})
	tunnel := tunnelSchema()
	value, _ := tunnel.Properties.Get("access")
	properties.Set("access", value)
	return &jsonschema.Schema{Type: "object", Required: []string{"service"}, Properties: properties, AdditionalProperties: jsonschema.FalseSchema,
		AllOf: []*jsonschema.Schema{
			{Not: &jsonschema.Schema{Required: []string{"name", "public_url"}}},
			{Not: &jsonschema.Schema{Required: []string{"domain", "public_url"}}},
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
