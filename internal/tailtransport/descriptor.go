package tailtransport

import (
	"errors"
	"fmt"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const descriptorVersion = 1

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

	region := profiles[e.RelayProfile]
	if region == nil || region.RegionID == 0 || len(region.Nodes) == 0 {
		return "", fmt.Errorf("invalid tailcat relay profile %q", e.RelayProfile)
	}
	for _, node := range region.Nodes {
		if node == nil {
			return "", fmt.Errorf("invalid tailcat relay profile %q", e.RelayProfile)
		}
	}

	return (&tailcat.ConnInfo{
		ServerPublic: tailcat.NodePublic{NodePublic: serverKey},
		Region:       []*tailcfg.DERPRegion{region},
	}).ConnBlob(), nil
}
