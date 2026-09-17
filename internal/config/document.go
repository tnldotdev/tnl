package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/json/jsontext"
	json "encoding/json/v2"

	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"go.yaml.in/yaml/v3"
)

const DocumentVersion = 1

// Document is the versioned static tnl.yml, tnl.yaml, or tnl.json contract.
// TypeScript configuration evaluates directly to TNL and is wrapped in this
// document shape by the loader.
type Document struct {
	Schema  string       `json:"$schema,omitempty" yaml:"$schema,omitempty"`
	Version *int         `json:"version" yaml:"version" jsonschema:"required"`
	TNL     *TNL         `json:"tnl,omitempty" yaml:"tnl,omitempty"`
	TNLD    *TNLDSection `json:"tnld,omitempty" yaml:"tnld,omitempty"`
}

// TNL contains project-local client configuration.
type TNL struct {
	Server   *string  `json:"server,omitempty" yaml:"server,omitempty"`
	Team     *string  `json:"team,omitempty" yaml:"team,omitempty"`
	Tunnel   *Tunnel  `json:"tunnel,omitempty" yaml:"tunnel,omitempty"`
	Publish  *Publish `json:"publish,omitempty" yaml:"publish,omitempty"`
	Dev      *Dev     `json:"dev,omitempty" yaml:"dev,omitempty"`
	Services Services `json:"services,omitempty" yaml:"services,omitempty"`
}

type Services map[string]Service

// Service contains project-local overrides for one named local service.
type Service struct {
	Directory *string  `json:"directory,omitempty" yaml:"directory,omitempty"`
	Server    *string  `json:"server,omitempty" yaml:"server,omitempty"`
	Team      *string  `json:"team,omitempty" yaml:"team,omitempty"`
	Tunnel    *Tunnel  `json:"tunnel,omitempty" yaml:"tunnel,omitempty"`
	Publish   *Publish `json:"publish,omitempty" yaml:"publish,omitempty"`
	Dev       *Dev     `json:"dev,omitempty" yaml:"dev,omitempty"`
}

type Tunnel struct {
	Host      *string  `json:"host,omitempty" yaml:"host,omitempty"`
	Subdomain *string  `json:"subdomain,omitempty" yaml:"subdomain,omitempty"`
	AllowIP   []string `json:"allow_ip,omitempty" yaml:"allow_ip,omitempty" jsonschema:"maxItems=63,uniqueItems=true"`
	Public    *bool    `json:"public,omitempty" yaml:"public,omitempty"`
	Ephemeral *bool    `json:"ephemeral,omitempty" yaml:"ephemeral,omitempty"`
}

type Publish struct {
	Target *Target `json:"target,omitempty" yaml:"target,omitempty"`
}

type Dev struct {
	Command        []string  `json:"command,omitempty" yaml:"command,omitempty" jsonschema:"minItems=1"`
	Port           *int      `json:"port,omitempty" yaml:"port,omitempty" jsonschema:"minimum=1,maximum=65535"`
	StartupTimeout *Duration `json:"startup_timeout,omitempty" yaml:"startup_timeout,omitempty"`
}

// Target accepts either a local HTTP URL or a literal port.
type Target string

func (t *Target) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		*t = Target(text)
		return nil
	}
	var port int
	if err := json.Unmarshal(data, &port); err != nil {
		return errors.New("target must be a string or integer port")
	}
	*t = Target(strconv.Itoa(port))
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

// DurationPattern describes the positive Go duration syntax accepted by
// project configuration. Semantic bounds are checked after decoding.
const DurationPattern = `^([0-9]+(\.[0-9]+)?|\.[0-9]+)(ns|us|\u00b5s|ms|s|m|h)(([0-9]+(\.[0-9]+)?|\.[0-9]+)(ns|us|\u00b5s|ms|s|m|h))*$`

var durationSyntax = regexp.MustCompile(strings.ReplaceAll(DurationPattern, `\u00b5`, `\x{00b5}`))

// Duration is a Go duration string in project configuration.
type Duration time.Duration

func (d Duration) Value() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("duration must be a string")
	}
	if !durationSyntax.MatchString(value) {
		return errors.New("invalid duration syntax")
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	*d = Duration(parsed)
	return nil
}

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return errors.New("duration must be a string")
	}
	if !durationSyntax.MatchString(node.Value) {
		return errors.New("invalid duration syntax")
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	*d = Duration(parsed)
	return nil
}

// TNLDSection is a presence-aware partial tnldconfig.Config value. Its field
// names and types are derived from Config so file configuration cannot drift
// from flags.
type TNLDSection struct {
	value   tnldconfig.Config
	present map[int]bool
}

func (s TNLDSection) Value() tnldconfig.Config { return s.value }

// Apply replaces only fields explicitly present in the file.
func (s TNLDSection) Apply(target *tnldconfig.Config) {
	s.apply(target, nil, false)
}

// ApplyLowerPrecedence applies file fields unless a command-line flag or one
// of the field's TNLD_* environment variables supplied a higher-precedence value.
func (s TNLDSection) ApplyLowerPrecedence(target *tnldconfig.Config, commandLine map[string]bool) map[string]bool {
	return s.apply(target, commandLine, true)
}

func (s TNLDSection) apply(target *tnldconfig.Config, commandLine map[string]bool, respectHigherPrecedence bool) map[string]bool {
	applied := make(map[string]bool)
	if target == nil {
		return applied
	}
	sourceValue := reflect.ValueOf(s.value)
	targetValue := reflect.ValueOf(target).Elem()
	typeOfConfig := reflect.TypeOf(tnldconfig.Config{})
	for index := range s.present {
		field := typeOfConfig.Field(index)
		name := strings.ReplaceAll(field.Tag.Get("name"), "-", "_")
		if respectHigherPrecedence && (commandLine[name] || environmentConfigured(field.Tag.Get("env"))) {
			continue
		}
		targetValue.Field(index).Set(sourceValue.Field(index))
		applied[name] = true
	}
	return applied
}

func environmentConfigured(names string) bool {
	for _, name := range strings.Split(names, ",") {
		if name != "" {
			if _, ok := os.LookupEnv(name); ok {
				return true
			}
		}
	}
	return false
}

func (s *TNLDSection) UnmarshalJSON(data []byte) error {
	var values map[string]jsontext.Value
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	for name, data := range values {
		field, ok := tnldFields()[name]
		if !ok {
			return fmt.Errorf("unknown tnld field %q", name)
		}
		value := reflect.ValueOf(&s.value).Elem().Field(field.index)
		if field.duration {
			var text string
			if err := json.Unmarshal(data, &text); err != nil {
				return fmt.Errorf("tnld.%s must be a duration string", name)
			}
			parsed, err := time.ParseDuration(text)
			if err != nil {
				return fmt.Errorf("tnld.%s: invalid duration", name)
			}
			value.SetInt(int64(parsed))
		} else if err := json.Unmarshal(data, value.Addr().Interface(), json.RejectUnknownMembers(true)); err != nil {
			return fmt.Errorf("tnld.%s: %w", name, err)
		}
		s.markPresent(field.index)
	}
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

func (s *TNLDSection) markPresent(index int) {
	if s.present == nil {
		s.present = make(map[int]bool)
	}
	s.present[index] = true
}

type tnldField struct {
	index    int
	duration bool
}

var (
	tnldFieldsOnce sync.Once
	tnldFieldMap   map[string]tnldField
)

func tnldFields() map[string]tnldField {
	tnldFieldsOnce.Do(func() {
		typeOfConfig := reflect.TypeOf(tnldconfig.Config{})
		durationType := reflect.TypeOf(time.Duration(0))
		tnldFieldMap = make(map[string]tnldField, typeOfConfig.NumField())
		for index := 0; index < typeOfConfig.NumField(); index++ {
			field := typeOfConfig.Field(index)
			name := strings.ReplaceAll(field.Tag.Get("name"), "-", "_")
			if name == "" || name == "database_direct_url" {
				continue
			}
			tnldFieldMap[name] = tnldField{index: index, duration: field.Type == durationType}
		}
	})
	return tnldFieldMap
}
