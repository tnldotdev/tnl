package config

import (
	"encoding/json"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
)

func TestSelectedRelayMapContainsOnlyRequestedRegion(t *testing.T) {
	profiles := map[string]*tailcfg.DERPRegion{
		"first":  {RegionID: 1, RegionCode: "first"},
		"second": {RegionID: 2, RegionCode: "second"},
	}
	data, err := SelectedRelayMap(profiles, "second")
	if err != nil {
		t.Fatal(err)
	}
	var relayMap tailcfg.DERPMap
	if err := json.Unmarshal(data, &relayMap); err != nil {
		t.Fatal(err)
	}
	if len(relayMap.Regions) != 1 || relayMap.Regions[2] == nil || relayMap.Regions[2].RegionCode != "second" {
		t.Fatalf("regions = %#v", relayMap.Regions)
	}
}

func TestSelectedRelayMapRejectsClientIncompatibleSize(t *testing.T) {
	profiles := map[string]*tailcfg.DERPRegion{"large": {
		RegionID: 1, RegionCode: "large", Nodes: []*tailcfg.DERPNode{{
			Name: "large", RegionID: 1, HostName: strings.Repeat("x", maxSelectedRelayMapBytes), DERPPort: 443,
		}},
	}}
	if _, err := SelectedRelayMap(profiles, "large"); err == nil {
		t.Fatal("oversized selected relay map accepted")
	}
}
