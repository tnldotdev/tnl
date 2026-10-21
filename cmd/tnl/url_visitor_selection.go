package main

import (
	"context"
	"strings"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func resolveVisitorPublicURL(ctx context.Context, session *teamSession, selector string) (controlv1.AvailablePublicURL, error) {
	items, err := visitorURLList(ctx, session.authenticated.Control, "")
	if err != nil {
		return controlv1.AvailablePublicURL{}, err
	}
	hostname := strings.TrimSuffix(strings.TrimPrefix(selector, "https://"), "/")
	for _, item := range items {
		if item.Id == selector || item.CanonicalHostname == hostname {
			return item, nil
		}
	}
	return controlv1.AvailablePublicURL{}, failure.Wrap("select visitor public URL", failure.ServerResourceNotFound, controlclient.ErrNotFound)
}
