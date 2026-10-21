package config

import (
	"errors"
	"fmt"

	"encoding/json/v2"

	"github.com/tnldotdev/tnl/internal/authorization"
	"go.yaml.in/yaml/v3"
)

// Access is the complete visitor policy. an IP list narrows its mode; it
// never grants access to a visitor without the mode's required credential.
type Access struct {
	Mode string   `json:"mode,omitempty" yaml:"mode,omitempty"`
	IP   []string `json:"ip,omitempty" yaml:"ip,omitempty"`
}

func (a Access) VisitorMode() string {
	if a.Mode == "" {
		return "restricted"
	}
	return a.Mode
}

func (a Access) Validate() error {
	if a.VisitorMode() != "restricted" && a.VisitorMode() != "anonymous" {
		return errors.New("access mode must be restricted or anonymous")
	}
	_, err := authorization.CanonicalizeIPPrefixes(a.IP)
	if err != nil || a.IP != nil && len(a.IP) == 0 || len(a.IP) > 256 {
		return errors.New("access IP list must contain distinct canonical addresses or prefixes")
	}
	for _, value := range a.IP {
		if !canonicalIPText(value) {
			return errors.New("access IP list must contain distinct canonical addresses or prefixes")
		}
	}
	return nil
}

func (a *Access) UnmarshalJSON(data []byte) error {
	var mode string
	if err := json.Unmarshal(data, &mode); err == nil {
		*a = Access{Mode: mode}
		return a.Validate()
	}
	type object Access
	var value object
	if err := json.Unmarshal(data, &value, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("access must be a mode or an object: %w", err)
	}
	*a = Access(value)
	return a.Validate()
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
