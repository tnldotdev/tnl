package config

import (
	"bytes"
	"errors"

	json "encoding/json/v2"

	"go.yaml.in/yaml/v3"
)

// WebhookSources admits published provider IP ranges, custom IPs, or every IP.
// provider identity and request signatures remain the local service's decision.
type WebhookSources struct {
	Providers []string `json:"providers,omitempty" yaml:"providers,omitempty"`
	IPs       []string `json:"ips,omitempty" yaml:"ips,omitempty"`
	any       bool
}

func (s WebhookSources) Any() bool { return s.any }

func AnyWebhookSources() WebhookSources { return WebhookSources{any: true} }

func (s *WebhookSources) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte(`"*"`)) {
		*s = WebhookSources{any: true}
		return nil
	}
	var value struct {
		Providers []string `json:"providers"`
		IPs       []string `json:"ips"`
	}
	if err := json.Unmarshal(data, &value, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return errors.New("allow_from must be an object or \"*\"")
	}
	*s = WebhookSources{Providers: value.Providers, IPs: value.IPs}
	return nil
}

func (s WebhookSources) MarshalJSON() ([]byte, error) {
	if s.any {
		return []byte(`"*"`), nil
	}
	return json.Marshal(struct {
		Providers []string `json:"providers,omitempty"`
		IPs       []string `json:"ips,omitempty"`
	}{s.Providers, s.IPs})
}

func (s *WebhookSources) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" && node.Value == "*" {
		*s = WebhookSources{any: true}
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return errors.New("allow_from must be a mapping or \"*\"")
	}
	for index := 0; index < len(node.Content); index += 2 {
		switch node.Content[index].Value {
		case "providers", "ips":
		default:
			return errors.New("allow_from contains an unknown field")
		}
	}
	var value struct {
		Providers []string `yaml:"providers"`
		IPs       []string `yaml:"ips"`
	}
	if err := node.Decode(&value); err != nil {
		return err
	}
	*s = WebhookSources{Providers: value.Providers, IPs: value.IPs}
	return nil
}
