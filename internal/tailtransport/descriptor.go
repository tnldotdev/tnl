package tailtransport

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const descriptorVersion = 1

// Endpoint is the trusted subset of Tailcat connection information exchanged
// between the hosted service and an agent.
type Endpoint struct {
	Version         int    `json:"version"`
	ServerPublicKey string `json:"server_public_key"`
	RelayProfile    string `json:"relay_profile"`
}

func (e Endpoint) connBlob(profiles map[string]*tailcfg.DERPRegion) (tailcat.ConnBlob, error) {
	if e.Version != descriptorVersion {
		return "", fmt.Errorf("unsupported tailcat descriptor version %d", e.Version)
	}

	var serverKey key.NodePublic
	if err := serverKey.UnmarshalText([]byte(e.ServerPublicKey)); err != nil || serverKey.IsZero() {
		return "", errors.New("invalid tailcat server public key")
	}

	region, err := relayRegion(e.RelayProfile, profiles)
	if err != nil {
		return "", err
	}

	return (&tailcat.ConnInfo{
		ServerPublic: tailcat.NodePublic{NodePublic: serverKey},
		Region:       []*tailcfg.DERPRegion{region},
	}).ConnBlob(), nil
}

func relayRegion(profile string, profiles map[string]*tailcfg.DERPRegion) (*tailcfg.DERPRegion, error) {
	region := profiles[profile]
	if profile == "" || !validRegion(region) {
		return nil, fmt.Errorf("invalid tailcat relay profile %q", profile)
	}
	return region.Clone(), nil
}

func validRegion(region *tailcfg.DERPRegion) bool {
	if region == nil || region.RegionID == 0 || len(region.Nodes) == 0 {
		return false
	}
	usable := false
	for _, node := range region.Nodes {
		if node == nil {
			return false
		}
		if node.STUNOnly {
			continue
		}
		if node.HostName != "" || validDERPAddress(node.IPv4) || validDERPAddress(node.IPv6) {
			usable = true
		}
	}
	return usable
}

func validDERPAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && !address.IsUnspecified()
}
