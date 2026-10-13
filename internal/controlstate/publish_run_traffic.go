package controlstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
)

func readPublishRunTrafficLimits(ctx context.Context, queries *controlstatedb.Queries, runID string) (*trafficlimits.Limits, error) {
	data, err := queries.GetPublishRunTrafficLimits(ctx, runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // runs from controls without traffic selection use ingress defaults.
	}
	if err != nil {
		return nil, fmt.Errorf("controlstate: read publish run traffic limits: %w", err)
	}
	var limits trafficlimits.Limits
	if err := json.Unmarshal(data, &limits); err != nil || !limits.Valid() || limits.RatePer == 0 {
		return nil, errors.New("controlstate: stored publish run traffic limits are invalid")
	}
	return &limits, nil
}
