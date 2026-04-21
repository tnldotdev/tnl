package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
)

const (
	maxRelayMapBytes         = 1 << 20
	maxSelectedRelayMapBytes = 64 << 10
	pinnedRelayMapName       = "relay-map.json"
)

func LoadRelayProfiles(path string) (map[string]*tailcfg.DERPRegion, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read relay map: %w", err)
	}
	return DecodeRelayProfiles(data)
}

// SelectRelayProfile validates and selects one configured relay region.
func SelectRelayProfile(
	profiles map[string]*tailcfg.DERPRegion,
	requested string,
) (string, error) {
	if requested != "" {
		region := profiles[requested]
		if err := validateRelayRegion(region); err != nil {
			return "", fmt.Errorf("relay profile %q: %w", requested, err)
		}
		return requested, nil
	}
	if len(profiles) == 1 {
		for profile, region := range profiles {
			if err := validateRelayRegion(region); err != nil {
				return "", fmt.Errorf("relay profile %q: %w", profile, err)
			}
			return profile, nil
		}
	}
	available := make([]string, 0, len(profiles))
	for profile := range profiles {
		available = append(available, profile)
	}
	sort.Strings(available)
	return "", fmt.Errorf("relay profile is required; available profiles: %s", strings.Join(available, ", "))
}

// LoadTailcatRelayProfiles loads the pinned Tailcat region or selects and persists one.
func LoadTailcatRelayProfiles(
	ctx context.Context,
	stateDir string,
	refresh bool,
) (map[string]*tailcfg.DERPRegion, string, error) {
	path := filepath.Join(stateDir, pinnedRelayMapName)
	if !refresh {
		profiles, err := LoadRelayProfiles(path)
		if err == nil {
			profile, selectErr := SelectRelayProfile(profiles, "")
			return profiles, profile, selectErr
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, "", err
		}
	}

	relayMap, err := tailcat.FetchDERPMap(ctx, tailcat.ExpandForServer)
	if err != nil {
		return nil, "", fmt.Errorf("fetch Tailcat relay map: %w", err)
	}
	regionID, err := tailcat.PickBestRegion(ctx, relayMap)
	if err != nil {
		return nil, "", fmt.Errorf("select Tailcat relay region: %w", err)
	}
	region := relayMap.Regions[regionID]
	if err := validateRelayRegion(region); err != nil {
		return nil, "", fmt.Errorf("selected Tailcat relay region: %w", err)
	}
	data, err := json.Marshal(tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{region.RegionID: region.Clone()},
	})
	if err != nil {
		return nil, "", fmt.Errorf("encode Tailcat relay region: %w", err)
	}
	if len(data) > maxSelectedRelayMapBytes {
		return nil, "", errors.New("selected Tailcat relay region exceeds 64 KiB")
	}
	if err := writePinnedRelayMap(stateDir, path, data); err != nil {
		return nil, "", err
	}
	profiles, err := DecodeRelayProfiles(data)
	if err != nil {
		return nil, "", err
	}
	return profiles, region.RegionCode, nil
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

func validateRelayRegion(region *tailcfg.DERPRegion) error {
	if region == nil || region.RegionID <= 0 || !validRelayProfile(region.RegionCode) || len(region.Nodes) == 0 {
		return errors.New("region is incomplete")
	}
	usable := false
	for _, node := range region.Nodes {
		if node == nil || node.RegionID != 0 && node.RegionID != region.RegionID ||
			node.InsecureForTests || node.STUNTestIP != "" {
			return errors.New("region contains an invalid node")
		}
		if node.STUNOnly {
			continue
		}
		if node.HostName != "" || validRelayAddress(node.IPv4) || validRelayAddress(node.IPv6) {
			usable = true
		}
	}
	if !usable {
		return errors.New("region contains no usable DERP node")
	}
	return nil
}

func validRelayAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && !address.IsUnspecified()
}

func writePinnedRelayMap(stateDir, path string, data []byte) error {
	file, err := os.CreateTemp(stateDir, ".relay-map-*")
	if err != nil {
		return fmt.Errorf("create pinned relay map: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("secure pinned relay map: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write pinned relay map: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync pinned relay map: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close pinned relay map: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace pinned relay map: %w", err)
	}
	directory, err := os.Open(stateDir)
	if err != nil {
		return fmt.Errorf("open relay map directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync relay map directory: %w", err)
	}
	return nil
}
