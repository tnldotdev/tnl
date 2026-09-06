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
	if err := writeFile(filepath.Join(root, "internal", "tnlts", "keys.gen.json"), append(data, '\n')); err != nil {
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
	case reflect.TypeOf(config.TNLDSection{}):
		return tnldSchema()
	default:
		return nil
	}
}

func servicesSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	properties.Set("directory", &jsonschema.Schema{Type: "string", MinLength: integerPointer(1)})
	properties.Set("server", &jsonschema.Schema{Type: "string"})
	properties.Set("team", &jsonschema.Schema{Type: "string"})
	properties.Set("tunnel", tunnelSchema())
	properties.Set("publish", &jsonschema.Schema{Ref: "#/$defs/Publish"})
	properties.Set("dev", &jsonschema.Schema{Ref: "#/$defs/Dev"})
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
	properties.Set("host", &jsonschema.Schema{Type: "string"})
	properties.Set("subdomain", &jsonschema.Schema{Type: "string"})
	properties.Set("allow_ip", &jsonschema.Schema{
		Type: "array", Items: &jsonschema.Schema{Type: "string"}, MaxItems: integerPointer(63), UniqueItems: true,
	})
	properties.Set("public", &jsonschema.Schema{Type: "boolean"})
	properties.Set("ephemeral", &jsonschema.Schema{Type: "boolean"})
	publicProperties := jsonschema.NewProperties()
	publicProperties.Set("public", &jsonschema.Schema{Const: true})
	return &jsonschema.Schema{
		Type: "object", Properties: properties, AdditionalProperties: jsonschema.FalseSchema,
		AllOf: []*jsonschema.Schema{
			{Not: &jsonschema.Schema{Required: []string{"host", "subdomain"}}},
			{
				If:   &jsonschema.Schema{Properties: publicProperties, Required: []string{"public"}},
				Then: &jsonschema.Schema{Not: &jsonschema.Schema{Required: []string{"allow_ip"}}},
			},
		},
	}
}

func tnldSchema() *jsonschema.Schema {
	properties := jsonschema.NewProperties()
	typeOfTNLD := reflect.TypeOf(config.TNLD{})
	durationType := reflect.TypeOf(time.Duration(0))
	for index := 0; index < typeOfTNLD.NumField(); index++ {
		field := typeOfTNLD.Field(index)
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
	case reflect.Slice:
		return &jsonschema.Schema{Type: "array", Items: primitiveSchema(valueType.Elem(), false)}
	default:
		panic(fmt.Sprintf("unsupported TNLD field type %s", valueType))
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
	default:
		return value
	}
}

func collectTypeScriptKeys(valueType reflect.Type, result map[string]string) {
	for index := 0; index < valueType.NumField(); index++ {
		field := valueType.Field(index)
		staticName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if staticName == "" || staticName == "-" {
			continue
		}
		typeScriptName := field.Tag.Get("tnlts")
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
