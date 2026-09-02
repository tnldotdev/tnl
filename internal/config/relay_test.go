package config

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/state"
	"tailscale.com/tailcfg"
)

func TestSelectRelayRegion(t *testing.T) {
	region := &tailcfg.DERPRegion{
		RegionID: 1, RegionCode: "first", Nodes: []*tailcfg.DERPNode{{
			Name: "first", RegionID: 1, HostName: "relay.example", DERPPort: 443,
		}},
	}
	regions := map[string]*tailcfg.DERPRegion{"first": region}
	regionCode, err := SelectRelayRegion(regions, "")
	if err != nil {
		t.Fatal(err)
	}
	if regionCode != "first" {
		t.Fatalf("regionCode = %q, want first", regionCode)
	}

	regions["second"] = region.Clone()
	regions["second"].RegionID = 2
	regions["second"].RegionCode = "second"
	regions["second"].Nodes[0].RegionID = 2
	if _, err := SelectRelayRegion(regions, ""); err == nil {
		t.Fatal("multiple relay regions selected without an explicit regionCode")
	}
	if regionCode, err := SelectRelayRegion(regions, "second"); err != nil || regionCode != "second" {
		t.Fatalf("explicit regionCode = %q, %v", regionCode, err)
	}
	regions["second"].Nodes[0].InsecureForTests = true
	if _, err := SelectRelayRegion(regions, "second"); err == nil {
		t.Fatal("insecure relay regionCode accepted")
	}
}

func TestLoadTailcatRelayRegionsUsesPinnedMap(t *testing.T) {
	directory := t.TempDir()
	data := []byte(`{"Regions":{"1":{"RegionID":1,"RegionCode":"pinned","Nodes":[{"Name":"pinned","RegionID":1,"HostName":"relay.example","DERPPort":443}]}}}`)
	db, err := state.Open(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := state.WriteRelayMap(t.Context(), db, data); err != nil {
		t.Fatal(err)
	}
	regions, regionCode, err := LoadTailcatRelayRegions(t.Context(), db, false)
	if err != nil {
		t.Fatal(err)
	}
	if regionCode != "pinned" || regions[regionCode] == nil {
		t.Fatalf("regions = %#v, selected = %q", regions, regionCode)
	}
}

func TestSelectedRelayMapContainsOnlyRequestedRegion(t *testing.T) {
	regions := map[string]*tailcfg.DERPRegion{
		"first":  {RegionID: 1, RegionCode: "first"},
		"second": {RegionID: 2, RegionCode: "second"},
	}
	data, err := SelectedRelayMap(regions, "second")
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
	regions := map[string]*tailcfg.DERPRegion{"large": {
		RegionID: 1, RegionCode: "large", Nodes: []*tailcfg.DERPNode{{
			Name: "large", RegionID: 1, HostName: strings.Repeat("x", maxSelectedRelayMapBytes), DERPPort: 443,
		}},
	}}
	if _, err := SelectedRelayMap(regions, "large"); err == nil {
		t.Fatal("oversized selected relay map accepted")
	}
}
