package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// validateYAMLValueTypes prevents YAML's scalar coercions from changing the
// contract accepted by JSON and TypeScript configuration.
func validateYAMLValueTypes(node *yaml.Node, typ reflect.Type, active map[*yaml.Node]bool) error {
	if active[node] {
		return errors.New("recursive YAML aliases are not supported")
	}
	active[node] = true
	defer delete(active, node)
	if node.Kind == yaml.AliasNode {
		return validateYAMLValueTypes(node.Alias, typ, active)
	}
	if node.Tag == "!!null" {
		return errors.New("configuration values must not be null; omit optional fields")
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf(TNLDSection{}) {
		return nil
	}
	if typ == reflect.TypeOf(Target("")) {
		if node.Kind == yaml.ScalarNode && (node.Tag == "!!str" || node.Tag == "!!int") {
			return nil
		}
		return errors.New("target address must be a string or integer port")
	}
	if typ == reflect.TypeOf(Duration(0)) || typ == reflect.TypeOf(ByteSize(0)) || typ == reflect.TypeOf(time.Duration(0)) {
		if node.Tag != "!!str" {
			return errors.New("duration and byte sizes must be strings")
		}
		return nil
	}
	if (typ == reflect.TypeOf(PathMount{}) || typ == reflect.TypeOf(Access{})) && node.Tag == "!!str" {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		if node.Kind != yaml.MappingNode {
			return errors.New("configuration object is required")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			if name != "" && name != "-" {
				fields[name] = field.Type
			}
		}
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Tag == "!!merge" {
				if value.Kind == yaml.SequenceNode {
					for _, merged := range value.Content {
						if err := validateYAMLValueTypes(merged, typ, active); err != nil {
							return err
						}
					}
				} else if err := validateYAMLValueTypes(value, typ, active); err != nil {
					return err
				}
				continue
			}
			if key.Tag != "!!str" {
				return errors.New("configuration field names must be strings")
			}
			if fieldType, found := fields[key.Value]; found {
				if err := validateYAMLValueTypes(value, fieldType, active); err != nil {
					return fmt.Errorf("%s: %w", key.Value, err)
				}
			}
		}
	case reflect.Map:
		if node.Kind != yaml.MappingNode {
			return errors.New("configuration map is required")
		}
		for i := 0; i < len(node.Content); i += 2 {
			if node.Content[i].Tag != "!!str" {
				return errors.New("configuration map keys must be strings")
			}
			if err := validateYAMLValueTypes(node.Content[i+1], typ.Elem(), active); err != nil {
				return fmt.Errorf("%s: %w", node.Content[i].Value, err)
			}
		}
	case reflect.Slice:
		if node.Kind != yaml.SequenceNode {
			return errors.New("configuration list is required")
		}
		for _, value := range node.Content {
			if err := validateYAMLValueTypes(value, typ.Elem(), active); err != nil {
				return err
			}
		}
	case reflect.String:
		if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
			return errors.New("configuration string is required")
		}
	case reflect.Bool:
		if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
			return errors.New("configuration boolean is required")
		}
	case reflect.Int, reflect.Int64:
		if node.Kind != yaml.ScalarNode || node.Tag != "!!int" {
			return errors.New("configuration integer is required")
		}
	}
	return nil
}

// RejectNullValues checks decoded external JSON before pointer fields can turn
// an explicit null into an omitted value.
func RejectNullValues(value any) error {
	switch v := value.(type) {
	case nil:
		return errors.New("configuration values must not be null; omit optional fields")
	case map[string]any:
		for name, child := range v {
			if err := RejectNullValues(child); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	case []any:
		for _, child := range v {
			if err := RejectNullValues(child); err != nil {
				return err
			}
		}
	}
	return nil
}
