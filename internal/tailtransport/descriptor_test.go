package tailtransport

import (
	"testing"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestEndpointConnBlob(t *testing.T) {
	serverKey := key.NewNode().Public()
	region := &tailcfg.DERPRegion{
		RegionID: 1,
		Nodes:    []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example.com"}},
	}
	endpoint := Endpoint{
		Version:         descriptorVersion,
		ServerPublicKey: serverKey.String(),
		RelayProfile:    "test",
	}

	blob, err := endpoint.connBlob(map[string]*tailcfg.DERPRegion{"test": region})
	if err != nil {
		t.Fatalf("connBlob: %v", err)
	}
	info, err := tailcat.ParseConnBlob(blob)
	if err != nil {
		t.Fatalf("ParseConnBlob: %v", err)
	}
	if info.ServerPublic.NodePublic != serverKey {
		t.Fatalf("server key = %v; want %v", info.ServerPublic.NodePublic, serverKey)
	}
	if len(info.Region) != 1 || len(info.Region[0].Nodes) != 1 || info.Region[0].Nodes[0].HostName != "derp.example.com" {
		t.Fatalf("region = %+v; want configured test region", info.Region)
	}
}

func TestEndpointConnBlobRejectsInvalidDescriptor(t *testing.T) {
	validKey := key.NewNode().Public().String()
	validRegion := &tailcfg.DERPRegion{RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1}}}
	tests := []struct {
		name     string
		endpoint Endpoint
		profiles map[string]*tailcfg.DERPRegion
	}{
		{"version", Endpoint{Version: 2, ServerPublicKey: validKey, RelayProfile: "test"}, map[string]*tailcfg.DERPRegion{"test": validRegion}},
		{"key", Endpoint{Version: descriptorVersion, ServerPublicKey: "nodekey:bad", RelayProfile: "test"}, map[string]*tailcfg.DERPRegion{"test": validRegion}},
		{"profile", Endpoint{Version: descriptorVersion, ServerPublicKey: validKey, RelayProfile: "missing"}, map[string]*tailcfg.DERPRegion{"test": validRegion}},
		{"profile node", Endpoint{Version: descriptorVersion, ServerPublicKey: validKey, RelayProfile: "test"}, map[string]*tailcfg.DERPRegion{"test": {RegionID: 1, Nodes: []*tailcfg.DERPNode{nil}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.endpoint.connBlob(test.profiles); err == nil {
				t.Fatal("connBlob unexpectedly succeeded")
			}
		})
	}
}
