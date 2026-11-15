package main

import (
	"context"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func resolveVisitorService(ctx context.Context, session *clientteam.Session, selector string) (controlv1.ServiceSummary, error) {
	items, err := visitorURLList(ctx, session.Authenticated().Control, "")
	if err != nil {
		return controlv1.ServiceSummary{}, err
	}
	return selectShareService(selector, items)
}
