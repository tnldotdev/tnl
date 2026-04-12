package tailbench

import (
	"context"
	"fmt"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
)

const RelayProfile = "public-derp"

type Endpoint struct {
	Version         int    `json:"version"`
	ServerPublicKey string `json:"server_public_key"`
	RelayProfile    string `json:"relay_profile"`
}

type Resources struct {
	HeapAlloc  uint64 `json:"heap_alloc"`
	Sys        uint64 `json:"sys"`
	RSS        int64  `json:"rss"`
	Goroutines int    `json:"goroutines"`
	OpenFDs    int    `json:"open_fds"`
}

type CreateRunRequest struct {
	ClientPublicKeys []string `json:"client_public_keys"`
}

type CreateRunResponse struct {
	Endpoints []Endpoint `json:"endpoints"`
	Before    Resources  `json:"before"`
	Ready     Resources  `json:"ready"`
}

type CloseRunResponse struct {
	After Resources `json:"after"`
}

func PublicRegion(ctx context.Context, regionID int) (*tailcfg.DERPRegion, error) {
	derpMap, err := tailcat.FetchDERPMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch public DERP map: %w", err)
	}
	region := derpMap.Regions[regionID]
	if region == nil {
		return nil, fmt.Errorf("public DERP region %d not found", regionID)
	}
	return region.Clone(), nil
}
