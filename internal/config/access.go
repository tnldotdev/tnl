package config

import (
	"errors"
	"fmt"

	"encoding/json/v2"

	"github.com/tnldotdev/tnl/internal/policy/authorization"
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

// Validate replaces IP with its canonical value only after validation succeeds.
func (a *Access) Validate() error {
	if a.VisitorMode() != "restricted" && a.VisitorMode() != "anonymous" {
		return errors.New("access mode must be restricted or anonymous")
	}
	if a.IP != nil && len(a.IP) == 0 {
		return errors.New("access.ip must not be empty")
	}
	prefixes, err := authorization.CanonicalizeVisitorIPPrefixes(a.IP)
	if err != nil {
		return fmt.Errorf("access.ip: %w", err)
	}
	a.IP = prefixes
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
