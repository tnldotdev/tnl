package project

import (
	json "encoding/json/v2"

	"github.com/tnldotdev/tnl/internal/config"
)

// StaticMap returns the validated snake_case configuration shape for consumers
// that map declarations into control APIs. it contains configured selectors,
// never AWS discovery results. callers resolve source identity separately.
func (p Project) StaticMap() (map[string]any, error) {
	declaration := p.Config
	if p.Declared != nil {
		declaration = *p.Declared
	}
	if err := config.ValidateTNL(declaration); err != nil {
		return nil, err
	}
	data, err := json.Marshal(declaration)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}
