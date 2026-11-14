package httpprotection

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"go.yaml.in/yaml/v3"
)

type Challenge string

const Turnstile Challenge = "turnstile"

const (
	ChallengeAttemptLifetime = 5 * time.Minute
	ChallengeHandoffLifetime = time.Minute
)

func (c Challenge) MarshalJSON() ([]byte, error) {
	switch c {
	case "":
		return []byte("false"), nil
	case Turnstile:
		return json.Marshal(string(c))
	default:
		return nil, errors.New("challenge must be turnstile or false")
	}
}

func (c *Challenge) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("false")) {
		*c = ""
		return nil
	}
	var value string
	if json.Unmarshal(data, &value) != nil || value != string(Turnstile) {
		return errors.New("challenge must be turnstile or false")
	}
	*c = Turnstile
	return nil
}

func (c *Challenge) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		if node.Tag == "!!bool" && node.Value == "false" {
			*c = ""
			return nil
		}
		if node.Tag == "!!str" && node.Value == string(Turnstile) {
			*c = Turnstile
			return nil
		}
	}
	return errors.New("challenge must be turnstile or false")
}
