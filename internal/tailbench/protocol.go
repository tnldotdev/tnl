package tailbench

import (
	"context"
	"fmt"

	"github.com/0xcadams/tnl/internal/processmetrics"
	"github.com/0xcadams/tnl/pkg/protocol/transportv1"
	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
)

const RelayProfile = "public-derp"

type Resources = processmetrics.Snapshot

type CreateRunRequest struct {
	ClientPublicKeys []string `json:"client_public_keys"`
}

type CreateRunResponse struct {
	Endpoints []transportv1.TailcatDescriptor `json:"endpoints"`
	Before    Resources                       `json:"before"`
	Ready     Resources                       `json:"ready"`
}

type CloseRunResponse struct {
	After        Resources `json:"after"`
	ForcedCloses int       `json:"forced_closes"`
	DrainError   string    `json:"drain_error,omitempty"`
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
