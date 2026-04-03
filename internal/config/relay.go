package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"tailscale.com/tailcfg"
)

const maxRelayMapBytes = 1 << 20

func LoadRelayProfiles(path string) (map[string]*tailcfg.DERPRegion, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read relay map: %w", err)
	}
	if len(data) == 0 || len(data) > maxRelayMapBytes {
		return nil, errors.New("relay map is empty or exceeds 1 MiB")
	}
	var relayMap tailcfg.DERPMap
	if err := json.Unmarshal(data, &relayMap); err != nil {
		return nil, fmt.Errorf("decode relay map: %w", err)
	}
	profiles := make(map[string]*tailcfg.DERPRegion, len(relayMap.Regions))
	for _, region := range relayMap.Regions {
		if region == nil || region.RegionCode == "" {
			return nil, errors.New("relay map contains a region without a code")
		}
		if _, exists := profiles[region.RegionCode]; exists {
			return nil, fmt.Errorf("relay map contains duplicate region code %q", region.RegionCode)
		}
		profiles[region.RegionCode] = region.Clone()
	}
	if len(profiles) == 0 {
		return nil, errors.New("relay map contains no regions")
	}
	return profiles, nil
}
