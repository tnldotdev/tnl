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
	keys["publisher_pool"] = "publisherPool"
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
	case reflect.TypeOf(config.Tunnel{}):
		return tunnelSchema()
	case reflect.TypeOf(config.Services{}):
		return servicesSchema()
	case reflect.TypeOf(config.CIGitHub{}):
		properties := jsonschema.NewProperties()
		properties.Set("repository", &jsonschema.Schema{Type: "string", Pattern: `^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`})
		properties.Set("workflow", &jsonschema.Schema{Type: "string", Pattern: `^\.github/workflows/[^/*?\[\]]+\.ya?ml$`})
		properties.Set("environment", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1)})
		properties.Set("ref", &jsonschema.Schema{Type: "string", Pattern: `^refs/(heads|tags)/[^*?\[\] ]+$`})
		properties.Set("reusable_workflow", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1)})
		events := []any{}
		for _, event := range config.CIEvents {
			events = append(events, event)
		}
		properties.Set("events", &jsonschema.Schema{Type: "array", MinItems: integerPointer(1), UniqueItems: true, Items: &jsonschema.Schema{Type: "string", Enum: events}})
		return &jsonschema.Schema{Type: "object", Properties: properties, Required: []string{"workflow", "ref", "events"}, AdditionalProperties: jsonschema.FalseSchema}
	case reflect.TypeOf(map[string]config.Publisher{}):
		properties := jsonschema.NewProperties()
		properties.Set("description", &jsonschema.Schema{Type: "string", MaxLength: integerPointer(1024)})
		properties.Set("domain", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1), MaxLength: integerPointer(253)})
		properties.Set("public", &jsonschema.Schema{Type: "boolean", Default: false})
		aws := jsonschema.NewProperties()
		aws.Set("replicas", &jsonschema.Schema{Type: "integer", Minimum: json.Number("1"), Maximum: json.Number(strconv.Itoa(config.MaxPublisherReplicas)), Default: 1})
		properties.Set("aws", &jsonschema.Schema{Type: "object", Properties: aws, AdditionalProperties: jsonschema.FalseSchema, Description: "Generate an AWS Fargate group stack; supply infrastructure settings as deployment parameters."})
		return &jsonschema.Schema{Type: "object", MaxProperties: integerPointer(32),
			PropertyNames:        &jsonschema.Schema{Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`, Not: &jsonschema.Schema{Const: "local"}},
			AdditionalProperties: &jsonschema.Schema{Type: "object", Properties: properties, AdditionalProperties: jsonschema.FalseSchema}}
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
			serviceSchema("http"), privateHTTPServiceSchema(), serviceSchema("tcp"), serviceSchema("mysql"), serviceSchema("postgres"), serviceSchema("kubernetes"),
		}},
	}
}

// serviceSchema keeps the protocol boundary in the generated TypeScript union,
// where JSON Schema conditionals alone would not constrain the declarations.
func serviceSchema(protocol string) *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set("name", &jsonschema.Schema{Type: "string", Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`, Description: "Saved name for either HTTP or private services; defaults to the service key."})
	properties.Set("publisher", &jsonschema.Schema{Type: "string", Pattern: `^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$`, Default: "local", Description: "Assigned publisher group; defaults to the built-in local publisher."})
	properties.Set("publisher_pool", jsonschema.FalseSchema)
	access := jsonschema.NewProperties()
	access.Set("team", &jsonschema.Schema{Type: "boolean", Const: true})
	properties.Set("access", &jsonschema.Schema{Type: "object", Properties: access, Required: []string{"team"}, AdditionalProperties: jsonschema.FalseSchema})
	properties.Set("inspection", &jsonschema.Schema{Ref: "#/$defs/Inspection"})
	tunnel := tunnelSchema()
	tunnel.Description = "Explicitly enable public HTTPS for this HTTP service. Omit this block for private HTTP. Root public URL defaults apply only when this block is present."
	limits, _ := tunnel.Properties.Get("limits")
	otherProtocol := "tcp"
	if protocol != "http" {
		otherProtocol = "http"
	}
	limits.Properties.Set(otherProtocol, jsonschema.FalseSchema)
	if protocol != "http" {
		properties.Set("public_url", jsonschema.FalseSchema)
	} else {
		properties.Set("public_url", tunnel)
	}
	protocols := []any{protocol}
	target := targetSchema(protocol)
	properties.Set("protocol", &jsonschema.Schema{Type: "string", Enum: protocols})
	properties.Set("target", target)
	properties.Set("tls", jsonschema.FalseSchema)
	httpProperties := jsonschema.NewProperties()
	readiness := jsonschema.NewProperties()
	readiness.Set("path", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1)})
	httpProperties.Set("readiness", &jsonschema.Schema{Type: "object", Properties: readiness, Required: []string{"path"}, AdditionalProperties: jsonschema.FalseSchema, Description: "Readiness probe for a local HTTP service. Remote publisher assignments do not support HTTP settings."})
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
		Description: "Mount another local HTTP service at a path on this local service's public URL. Remote publisher assignments do not support path mounts.",
	})
	properties.Set("http", &jsonschema.Schema{Type: "object", Properties: httpProperties, AdditionalProperties: jsonschema.FalseSchema})
	if protocol != "http" {
		properties.Set("http", jsonschema.FalseSchema)
	}
	service := &jsonschema.Schema{
		Type: "object", Properties: properties, AdditionalProperties: jsonschema.FalseSchema,
	}
	if protocol == "http" {
		service.Required = []string{"public_url"}
		conflict := jsonschema.NewProperties()
		conflict.Set("public_url", &jsonschema.Schema{Required: []string{"hostname"}})
		service.AllOf = []*jsonschema.Schema{{Not: &jsonschema.Schema{Required: []string{"name", "public_url"}, Properties: conflict}}}
	}
	if protocol != "http" {
		service.Required = []string{"protocol", "target"}
	}
	service.AllOf = append(service.AllOf, remotePublisherRestrictions())
	return service
}

func remotePublisherRestrictions() *jsonschema.Schema {
	selector := jsonschema.NewProperties()
	selector.Set("publisher", &jsonschema.Schema{Not: &jsonschema.Schema{Const: "local"}})
	restrictions := jsonschema.NewProperties()
	restrictions.Set("http", jsonschema.FalseSchema)
	target := jsonschema.NewProperties()
	target.Set("type", &jsonschema.Schema{Enum: []any{"address", "eks", "rds"}})
	restrictions.Set("target", &jsonschema.Schema{Properties: target, Required: []string{"type"}})
	return &jsonschema.Schema{
		If:   &jsonschema.Schema{Required: []string{"publisher"}, Properties: selector},
		Then: &jsonschema.Schema{Required: []string{"target"}, Properties: restrictions},
	}
}

func privateHTTPServiceSchema() *jsonschema.Schema {
	service := serviceSchema("http")
	service.Required = nil
	service.AllOf = []*jsonschema.Schema{remotePublisherRestrictions()}
	service.Properties.Set("public_url", jsonschema.FalseSchema)
	http, _ := service.Properties.Get("http")
	http.Properties.Set("paths", jsonschema.FalseSchema)
	return service
}

func tunnelSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	// explicit forbidden fields also reject inferred or non-fresh TypeScript
	// objects; the saved name and pool opt-in belong on the service only.
	properties.Set("name", jsonschema.FalseSchema)
	properties.Set("publisher_pool", jsonschema.FalseSchema)
	properties.Set("domain", &jsonschema.Schema{Type: "string", Description: "Ready team domain used for generated public URL hostnames."})
	properties.Set("hostname", &jsonschema.Schema{Type: "string", Description: "Exact public URL hostname or HTTPS origin to publish. The saved name belongs on the service, not inside publicURL."})
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
	}
}

func webhookSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set("service", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1), Description: "Configured local HTTP service with an explicit public_url block. App, address, Compose and Docker targets are supported."})
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

func targetSchema(protocol string) *jsonschema.Schema {
	variants := []*jsonschema.Schema{}
	for _, kind := range []string{"app", "address", "compose", "docker", "eks", "rds"} {
		if kind == "app" && protocol != "http" || kind == "eks" && protocol != "kubernetes" || kind == "rds" && protocol != "postgres" && protocol != "mysql" {
			continue
		}
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
		case "eks", "rds":
			properties.Set("region", &jsonschema.Schema{Type: "string", Pattern: `^[a-z]{2}(?:-[a-z]+)+-[0-9]+$`})
			properties.Set("cluster", &jsonschema.Schema{Type: "string", Pattern: `^[A-Za-z][A-Za-z0-9_-]{0,99}$`})
			required = append(required, "region")
			if kind == "eks" {
				required = append(required, "cluster")
			} else {
				properties.Set("instance", &jsonschema.Schema{Type: "string", Pattern: `^[A-Za-z][A-Za-z0-9_-]{0,99}$`})
				properties.Set("endpoint", &jsonschema.Schema{Type: "string", Enum: []any{"writer", "reader"}, Default: "writer"})
			}
		}
		if kind == "compose" || kind == "docker" {
			properties.Set("port", &jsonschema.Schema{Type: "integer", Minimum: "1", Maximum: "65535"})
		}
		tls := jsonschema.NewProperties()
		tls.Set("server_name", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1), MaxLength: integerPointer(253), Description: "Target certificate hostname or IP; defaults to the resolved target host. Required when applying an app target before its listener is known."})
		tls.Set("ca_file", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1), Description: "Project-relative CA-only PEM file added to system roots; omit for system roots only."})
		properties.Set("tls", &jsonschema.Schema{Type: "object", Properties: tls, AdditionalProperties: jsonschema.FalseSchema, Description: "Verified publisher-to-target TLS. The protocol selects PostgreSQL or MySQL native negotiation, or direct TLS for HTTP/TCP. Independent of mandatory managed visitor TLS; never falls back to plaintext or unverified TLS."})
		if kind == "eks" || kind == "rds" {
			properties.Set("tls", jsonschema.FalseSchema)
		}
		// explicit forbidden fields also reject structurally inferred mixed targets
		// in defineConfig, rather than relying on fresh-object excess checks.
		for _, field := range []string{"address", "project", "file", "service", "port", "container", "tls", "region", "cluster", "instance", "endpoint"} {
			if _, found := properties.Get(field); !found {
				properties.Set(field, jsonschema.FalseSchema)
			}
		}
		if kind == "rds" {
			for _, selector := range []string{"instance", "cluster"} {
				copyProperties := jsonschema.NewProperties()
				for pair := properties.Oldest(); pair != nil; pair = pair.Next() {
					copyProperties.Set(pair.Key, pair.Value)
				}
				other := "instance"
				if selector == "instance" {
					other = "cluster"
					copyProperties.Set("endpoint", &jsonschema.Schema{Type: "string", Const: "writer"})
				}
				copyProperties.Set(other, jsonschema.FalseSchema)
				variants = append(variants, &jsonschema.Schema{Type: "object", Properties: copyProperties, Required: append(append([]string{}, required...), selector), AdditionalProperties: jsonschema.FalseSchema})
			}
		} else {
			variants = append(variants, &jsonschema.Schema{Type: "object", Properties: properties, Required: required, AdditionalProperties: jsonschema.FalseSchema})
		}
	}
	return &jsonschema.Schema{OneOf: variants}
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
	case reflect.Map:
		return &jsonschema.Schema{Type: "object", AdditionalProperties: primitiveSchema(valueType.Elem(), false)}
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
