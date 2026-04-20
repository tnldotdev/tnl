package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"tailscale.com/tailcfg"
)

const (
	maxRelayMapBytes         = 1 << 20
	maxSelectedRelayMapBytes = 64 << 10
)

func LoadRelayProfiles(path string) (map[string]*tailcfg.DERPRegion, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read relay map: %w", err)
	}
	return DecodeRelayProfiles(data)
}

func DecodeRelayProfiles(data []byte) (map[string]*tailcfg.DERPRegion, error) {
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

func SelectedRelayMap(profiles map[string]*tailcfg.DERPRegion, profile string) ([]byte, error) {
	region := profiles[profile]
	if region == nil {
		return nil, fmt.Errorf("relay profile %q is absent from the relay map", profile)
	}
	data, err := json.Marshal(tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{region.RegionID: region.Clone()},
	})
	if err != nil {
		return nil, fmt.Errorf("encode selected relay map: %w", err)
	}
	if len(data) > maxSelectedRelayMapBytes {
		return nil, errors.New("selected relay map exceeds 64 KiB")
	}
	return data, nil
}
