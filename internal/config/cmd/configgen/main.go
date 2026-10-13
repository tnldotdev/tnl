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
	"github.com/tnldotdev/tnl/internal/trafficlimits"
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
		return &jsonschema.Schema{Type: "string", Pattern: `^[1-9][0-9]*(KiB|MiB|GiB)$`}
	case reflect.TypeOf(config.ByteRate("")):
		return &jsonschema.Schema{Type: "string", Pattern: trafficlimits.ByteRatePattern}
	case reflect.TypeOf(config.Tunnel{}):
		return tunnelSchema()
	case reflect.TypeOf(config.Services{}):
		return servicesSchema()
	case reflect.TypeOf(config.ProjectPublisher{}):
		return projectPublisherSchema()
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

func projectPublisherSchema() *jsonschema.Schema {
	local := jsonschema.NewProperties()
	local.Set("type", &jsonschema.Schema{Const: "local"})
	url := jsonschema.NewProperties()
	url.Set("type", &jsonschema.Schema{Const: "url"})
	url.Set("url", &jsonschema.Schema{Type: "string", Pattern: `^https://[^/?#]+$`})
	url.Set("owner_credential_file", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1)})
	variants := []*jsonschema.Schema{
		{Type: "object", Required: []string{"type"}, Properties: local, AdditionalProperties: jsonschema.FalseSchema},
		{Type: "object", Required: []string{"type", "url"}, Properties: url, AdditionalProperties: jsonschema.FalseSchema},
	}
	for _, entry := range dockerSelectorSchemas("docker") {
		entry.Properties.Set("owner_credential_file", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1)})
		variants = append(variants, entry)
	}
	return &jsonschema.Schema{OneOf: variants}
}

func dockerSelectorSchemas(kind string, required ...string) []*jsonschema.Schema {
	selectors := []string{"container", "labels", "compose"}
	result := make([]*jsonschema.Schema, 0, len(selectors))
	for _, selector := range selectors {
		properties := jsonschema.NewProperties()
		properties.Set("type", &jsonschema.Schema{Const: kind})
		properties.Set("container_port", &jsonschema.Schema{Type: "integer", Minimum: "1", Maximum: "65535"})
		switch selector {
		case "container":
			properties.Set("container", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1)})
		case "labels":
			properties.Set("labels", &jsonschema.Schema{Type: "object", MinProperties: integerPointer(1), MaxProperties: integerPointer(8), AdditionalProperties: &jsonschema.Schema{Type: "string", MinLength: integerPointer(1)}})
		case "compose":
			compose := jsonschema.NewProperties()
			compose.Set("file", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1)})
			compose.Set("project", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1)})
			compose.Set("service", &jsonschema.Schema{Type: "string", Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`})
			properties.Set("compose", &jsonschema.Schema{Type: "object", Required: []string{"file", "project", "service"}, Properties: compose, AdditionalProperties: jsonschema.FalseSchema})
		}
		result = append(result, &jsonschema.Schema{Type: "object", Required: append([]string{"type", "container_port", selector}, required...), Properties: properties, AdditionalProperties: jsonschema.FalseSchema})
	}
	return result
}

func servicesSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set("inspection", &jsonschema.Schema{Ref: "#/$defs/Inspection"})
	appTargetProperties := jsonschema.NewProperties()
	appTargetProperties.Set("type", &jsonschema.Schema{Const: "app"})
	addressTargetProperties := jsonschema.NewProperties()
	addressTargetProperties.Set("type", &jsonschema.Schema{Const: "address"})
	addressTargetProperties.Set("address", schemaForType(reflect.TypeOf(config.Target(""))))
	tlsProperties := jsonschema.NewProperties()
	tlsProperties.Set("server_name", &jsonschema.Schema{Type: "string"})
	tlsProperties.Set("ca_file", &jsonschema.Schema{Type: "string"})
	tlsSchema := &jsonschema.Schema{Type: "object", Properties: tlsProperties, AdditionalProperties: jsonschema.FalseSchema}
	addressTargetProperties.Set("tls", tlsSchema)
	targetVariants := []*jsonschema.Schema{
		{Type: "object", Required: []string{"type"}, Properties: appTargetProperties, AdditionalProperties: jsonschema.FalseSchema},
		{Type: "object", Required: []string{"type", "address"}, Properties: addressTargetProperties, AdditionalProperties: jsonschema.FalseSchema},
	}
	for _, entry := range dockerSelectorSchemas("docker") {
		entry.Properties.Set("tls", tlsSchema)
		targetVariants = append(targetVariants, entry)
	}
	properties.Set("target", &jsonschema.Schema{OneOf: targetVariants})
	mountProperties := jsonschema.NewProperties()
	mountProperties.Set("service", &jsonschema.Schema{Type: "string", Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`})
	mountProperties.Set("strip_prefix", &jsonschema.Schema{Type: "boolean"})
	paths := &jsonschema.Schema{
		Type: "object", MaxProperties: integerPointer(32),
		AdditionalProperties: &jsonschema.Schema{OneOf: []*jsonschema.Schema{
			{Type: "string", Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`},
			{Type: "object", Required: []string{"service"}, Properties: mountProperties, AdditionalProperties: jsonschema.FalseSchema},
		}},
		Description: "Mount another configured service at a path on this service's public URL.",
	}
	httpProperties := jsonschema.NewProperties()
	readinessProperties := jsonschema.NewProperties()
	readinessProperties.Set("path", &jsonschema.Schema{Type: "string"})
	httpProperties.Set("paths", paths)
	httpProperties.Set("open", &jsonschema.Schema{Type: "boolean"})
	serviceVariant := func(protocol string, allowHTTP, allowTCP bool) *jsonschema.Schema {
		variant := jsonschema.NewProperties()
		for pair := properties.Oldest(); pair != nil; pair = pair.Next() {
			variant.Set(pair.Key, pair.Value)
		}
		variant.Set("protocol", &jsonschema.Schema{Const: protocol})
		tunnel := tunnelSchema()
		limitProperties := jsonschema.NewProperties()
		limitProperties.Set("traffic", trafficLimitsSchema())
		if allowHTTP {
			limitProperties.Set("http", workLimitsSchema())
			variant.Set("readiness", &jsonschema.Schema{Type: "object", Required: []string{"path"}, Properties: readinessProperties, AdditionalProperties: jsonschema.FalseSchema})
			variant.Set("http", &jsonschema.Schema{Type: "object", Properties: httpProperties, AdditionalProperties: jsonschema.FalseSchema})
		}
		if allowTCP {
			limitProperties.Set("tcp", workLimitsSchema())
			variant.Set("target", &jsonschema.Schema{OneOf: targetVariants[1:]})
			if protocol == "postgres" || protocol == "mysql" {
				tcp := jsonschema.NewProperties()
				tcp.Set("visitor_tls", &jsonschema.Schema{Type: "string", Enum: []any{"terminate", "passthrough"}})
				variant.Set("tcp", &jsonschema.Schema{Type: "object", Properties: tcp, AdditionalProperties: jsonschema.FalseSchema})
			}
		}
		tunnel.Properties.Set("limits", &jsonschema.Schema{Type: "object", Properties: limitProperties, AdditionalProperties: jsonschema.FalseSchema})
		variant.Set("tunnel", tunnel)
		required := []string{"protocol"}
		if protocol == "http" {
			required = nil
		} else {
			// TCP services must select a private target before publication.
			required = append(required, "target")
		}
		return &jsonschema.Schema{Type: "object", Required: required, Properties: variant, AdditionalProperties: jsonschema.FalseSchema}
	}
	var serviceVariants []*jsonschema.Schema
	for _, protocol := range []string{"http", "postgres", "mysql", "redis", "ssh"} {
		serviceVariants = append(serviceVariants, serviceVariant(protocol, protocol == "http", protocol != "http"))
	}
	service := &jsonschema.Schema{OneOf: serviceVariants}
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
	properties.Set("allow_ip", &jsonschema.Schema{
		Type: "array", Items: &jsonschema.Schema{Type: "string"}, UniqueItems: true,
		Description: "Visitor IP addresses or prefixes allowed to use the public URL; the current client IP is added automatically.",
	})
	properties.Set("allow_all_ips", &jsonschema.Schema{Type: "boolean", Description: "Allow visitors from every IP address."})
	properties.Set("ephemeral", &jsonschema.Schema{Type: "boolean", Description: "Remove the public URL when this tunnel stops."})
	limitProperties := jsonschema.NewProperties()
	limitProperties.Set("traffic", trafficLimitsSchema())
	limitProperties.Set("http", workLimitsSchema())
	limitProperties.Set("tcp", workLimitsSchema())
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

func trafficLimitsSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set("connections", &jsonschema.Schema{Type: "integer", Minimum: "1"})
	rate := jsonschema.NewProperties()
	rate.Set("count", &jsonschema.Schema{Type: "integer", Minimum: "1"})
	rate.Set("per", &jsonschema.Schema{Type: "string", Pattern: config.DurationPattern})
	rate.Set("burst", &jsonschema.Schema{Type: "integer", Minimum: "1"})
	properties.Set("rate", &jsonschema.Schema{Type: "object", Properties: rate, AdditionalProperties: jsonschema.FalseSchema})
	bandwidth := jsonschema.NewProperties()
	bandwidth.Set("upload", schemaForType(reflect.TypeOf(config.ByteRate(""))))
	bandwidth.Set("download", schemaForType(reflect.TypeOf(config.ByteRate(""))))
	properties.Set("bandwidth", &jsonschema.Schema{Type: "object", Properties: bandwidth, AdditionalProperties: jsonschema.FalseSchema})
	return &jsonschema.Schema{Type: "object", Properties: properties, AdditionalProperties: jsonschema.FalseSchema}
}

func workLimitsSchema() *jsonschema.Schema {
	limitProperties := jsonschema.NewProperties()
	limitProperties.Set("total", &jsonschema.Schema{Type: "integer", Minimum: "1"})
	rateProperties := jsonschema.NewProperties()
	rateProperties.Set("count", &jsonschema.Schema{Type: "integer", Minimum: "1"})
	rateProperties.Set("per", &jsonschema.Schema{Type: "string", Pattern: config.DurationPattern})
	rateProperties.Set("burst", &jsonschema.Schema{Type: "integer", Minimum: "1"})
	limitProperties.Set("rate", &jsonschema.Schema{Type: "object", Required: []string{"count", "per"}, Properties: rateProperties, AdditionalProperties: jsonschema.FalseSchema})
	limitProperties.Set("concurrency", &jsonschema.Schema{Type: "integer", Minimum: "1"})
	return &jsonschema.Schema{Type: "object", Properties: limitProperties, AdditionalProperties: jsonschema.FalseSchema}
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
		if field.Anonymous && staticName == "" && field.Type.Kind() == reflect.Struct {
			collectTypeScriptKeys(field.Type, result)
			continue
		}
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
