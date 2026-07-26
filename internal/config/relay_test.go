package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
)

func TestSelectRelayProfile(t *testing.T) {
	region := &tailcfg.DERPRegion{
		RegionID: 1, RegionCode: "first", Nodes: []*tailcfg.DERPNode{{
			Name: "first", RegionID: 1, HostName: "relay.example", DERPPort: 443,
		}},
	}
	profiles := map[string]*tailcfg.DERPRegion{"first": region}
	profile, err := SelectRelayProfile(profiles, "")
	if err != nil {
		t.Fatal(err)
	}
	if profile != "first" {
		t.Fatalf("profile = %q, want first", profile)
	}

	profiles["second"] = region.Clone()
	profiles["second"].RegionID = 2
	profiles["second"].RegionCode = "second"
	profiles["second"].Nodes[0].RegionID = 2
	if _, err := SelectRelayProfile(profiles, ""); err == nil {
		t.Fatal("multiple relay profiles selected without an explicit profile")
	}
	if profile, err := SelectRelayProfile(profiles, "second"); err != nil || profile != "second" {
		t.Fatalf("explicit profile = %q, %v", profile, err)
	}
	profiles["second"].Nodes[0].InsecureForTests = true
	if _, err := SelectRelayProfile(profiles, "second"); err == nil {
		t.Fatal("insecure relay profile accepted")
	}
}

func TestLoadTailcatRelayProfilesUsesPinnedMap(t *testing.T) {
	directory := t.TempDir()
	data := []byte(`{"Regions":{"1":{"RegionID":1,"RegionCode":"pinned","Nodes":[{"Name":"pinned","RegionID":1,"HostName":"relay.example","DERPPort":443}]}}}`)
	if err := os.WriteFile(filepath.Join(directory, pinnedRelayMapName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	profiles, profile, err := LoadTailcatRelayProfiles(t.Context(), directory, false)
	if err != nil {
		t.Fatal(err)
	}
	if profile != "pinned" || profiles[profile] == nil {
		t.Fatalf("profiles = %#v, selected = %q", profiles, profile)
	}
}

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
