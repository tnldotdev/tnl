package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/tailscale/tailcat"
	"github.com/tnldotdev/tnl/internal/state"
	"tailscale.com/tailcfg"
)

const (
	maxRelayMapBytes         = 1 << 20
	maxSelectedRelayMapBytes = 64 << 10
)

func LoadRelayRegions(path string) (map[string]*tailcfg.DERPRegion, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read relay map: %w", err)
	}
	return DecodeRelayRegions(data)
}

// SelectRelayRegion validates and selects one configured relay region.
func SelectRelayRegion(
	regions map[string]*tailcfg.DERPRegion,
	requested string,
) (string, error) {
	if requested != "" {
		region := regions[requested]
		if err := validateRelayRegion(region); err != nil {
			return "", fmt.Errorf("relay region %q: %w", requested, err)
		}
		return requested, nil
	}
	if len(regions) == 1 {
		for regionCode, region := range regions {
			if err := validateRelayRegion(region); err != nil {
				return "", fmt.Errorf("relay region %q: %w", regionCode, err)
			}
			return regionCode, nil
		}
	}
	available := make([]string, 0, len(regions))
	for regionCode := range regions {
		available = append(available, regionCode)
	}
	sort.Strings(available)
	return "", fmt.Errorf("relay region is required; available regions: %s", strings.Join(available, ", "))
}

// LoadTailcatRelayRegions loads the pinned Tailcat region or selects and persists one.
func LoadTailcatRelayRegions(
	ctx context.Context,
	db *sql.DB,
	refresh bool,
) (map[string]*tailcfg.DERPRegion, string, error) {
	if !refresh {
		data, err := state.ReadRelayMap(ctx, db)
		if err == nil {
			regions, err := DecodeRelayRegions(data)
			if err != nil {
				return nil, "", err
			}
			regionCode, selectErr := SelectRelayRegion(regions, "")
			return regions, regionCode, selectErr
		}
		if !errors.Is(err, sql.ErrNoRows) {
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
	if err := state.WriteRelayMap(ctx, db, data); err != nil {
		return nil, "", fmt.Errorf("persist Tailcat relay map: %w", err)
	}
	regions, err := DecodeRelayRegions(data)
	if err != nil {
		return nil, "", err
	}
	return regions, region.RegionCode, nil
}

func DecodeRelayRegions(data []byte) (map[string]*tailcfg.DERPRegion, error) {
	if len(data) == 0 || len(data) > maxRelayMapBytes {
		return nil, errors.New("relay map is empty or exceeds 1 MiB")
	}
	var relayMap tailcfg.DERPMap
	if err := json.Unmarshal(data, &relayMap); err != nil {
		return nil, fmt.Errorf("decode relay map: %w", err)
	}
	regions := make(map[string]*tailcfg.DERPRegion, len(relayMap.Regions))
	for _, region := range relayMap.Regions {
		if region == nil || region.RegionCode == "" {
			return nil, errors.New("relay map contains a region without a code")
		}
		if _, exists := regions[region.RegionCode]; exists {
			return nil, fmt.Errorf("relay map contains duplicate region code %q", region.RegionCode)
		}
		regions[region.RegionCode] = region.Clone()
	}
	if len(regions) == 0 {
		return nil, errors.New("relay map contains no regions")
	}
	return regions, nil
}

func SelectedRelayMap(regions map[string]*tailcfg.DERPRegion, regionCode string) ([]byte, error) {
	region := regions[regionCode]
	if region == nil {
		return nil, fmt.Errorf("relay region %q is absent from the relay map", regionCode)
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
	if region == nil || region.RegionID <= 0 || !validRelayRegion(region.RegionCode) || len(region.Nodes) == 0 {
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
