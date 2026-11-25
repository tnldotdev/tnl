package main

import (
	"context"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func resolveVisitorService(ctx context.Context, session *clientteam.Session, selector string) (controlv1.ServiceSummary, error) {
	input, err := parseWholeService(selector, failure.InvalidCommand)
	if err != nil {
		return controlv1.ServiceSummary{}, err
	}
	items, err := visitorURLList(ctx, session.Authenticated().Control, "")
	if err != nil {
		return controlv1.ServiceSummary{}, err
	}
	return matchInventory(input, items, failure.InvalidCommand)
}
