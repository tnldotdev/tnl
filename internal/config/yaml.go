//go:build !js || !wasm

package config

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"go.yaml.in/yaml/v3"
)

func (m *PathMount) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		*m = PathMount{Service: node.Value}
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return errors.New("path mount must be a service name or an object")
	}
	for index := 0; index < len(node.Content); index += 2 {
		switch node.Content[index].Value {
		case "service", "strip_prefix":
		default:
			return fmt.Errorf("unknown path mount field %q", node.Content[index].Value)
		}
	}
	type object PathMount
	var value object
	if err := node.Decode(&value); err != nil {
		return err
	}
	*m = PathMount(value)
	return nil
}

func (t *Target) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return errors.New("target must be a string or integer port")
	}
	if node.Tag == "!!int" {
		var port int
		if err := node.Decode(&port); err != nil {
			return errors.New("target must be a string or integer port")
		}
		*t = Target(strconv.Itoa(port))
		return nil
	}
	if node.Tag != "!!str" {
		return errors.New("target must be a string or integer port")
	}
	*t = Target(node.Value)
	return nil
}

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return errors.New("duration must be a string")
	}
	parsed, err := parseDuration(node.Value)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

func (s *TNLDSection) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("tnld must be an object")
	}
	seen := make(map[string]struct{}, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		key, valueNode := node.Content[index], node.Content[index+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return errors.New("tnld field names must be strings")
		}
		name := key.Value
		if _, ok := seen[name]; ok {
			return fmt.Errorf("tnld field %q is duplicated", name)
		}
		seen[name] = struct{}{}
		field, ok := tnldFields()[name]
		if !ok {
			return fmt.Errorf("unknown tnld field %q", name)
		}
		if err := validateYAMLValueTypes(valueNode, field.typ, make(map[*yaml.Node]bool)); err != nil {
			return fmt.Errorf("tnld.%s: %w", name, err)
		}
		value := reflect.ValueOf(&s.value).Elem().Field(field.index)
		if field.duration {
			if valueNode.Kind != yaml.ScalarNode || valueNode.Tag != "!!str" {
				return fmt.Errorf("tnld.%s must be a duration string", name)
			}
			parsed, err := time.ParseDuration(valueNode.Value)
			if err != nil {
				return fmt.Errorf("tnld.%s: invalid duration", name)
			}
			value.SetInt(int64(parsed))
		} else if err := valueNode.Decode(value.Addr().Interface()); err != nil {
			return fmt.Errorf("tnld.%s: %w", name, err)
		}
		s.markPresent(field.index)
	}
	return nil
}

func (size ByteSize) MarshalYAML() (any, error) { return size.text() }

func (size *ByteSize) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return errors.New("max_bytes must be a string")
	}
	value, err := ParseByteSize(node.Value)
	if err == nil {
		*size = value
	}
	return err
}

func (a *Access) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		*a = Access{Mode: node.Value}
		return a.Validate()
	}
	if node.Kind != yaml.MappingNode {
		return errors.New("access must be a mode or an object")
	}
	for i := 0; i < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "mode", "ip":
		default:
			return fmt.Errorf("unknown access field %q", node.Content[i].Value)
		}
	}
	type object Access
	var value object
	if err := node.Decode(&value); err != nil {
		return err
	}
	*a = Access(value)
	return a.Validate()
}
