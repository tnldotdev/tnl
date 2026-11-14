package control

import (
	"context"
	"errors"
	"math"
	"net/http"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) PreparePublicURLConnectorPeerPair(ctx context.Context, publicURLID string, body controlv1.PublicURLConnectorPeerPairRequest) (controlv1.PublicURLConnectorPeerPair, error) {
	return requestWithAccess[controlv1.PublicURLConnectorPeerPair](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.PreparePublicURLConnectorPeerPair(ctx, publicURLID, body, editors...)
	})
}

func (c *Client) RenewPublicURLConnectorPeerPair(ctx context.Context, publicURLID, pairID string, body controlv1.PublicURLConnectorPeerPairRequest) (controlv1.PublicURLConnectorPeerPairRenewal, error) {
	return requestWithAccess[controlv1.PublicURLConnectorPeerPairRenewal](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RenewPublicURLConnectorPeerPair(ctx, publicURLID, pairID, body, editors...)
	})
}

func (c *Client) RebindPublicURLConnectorPeerPair(ctx context.Context, publicURLID, pairID string, body controlv1.PublicURLConnectorPeerPairRebindRequest) (controlv1.PublicURLConnectorPeerPairRebindState, error) {
	return requestWithAccess[controlv1.PublicURLConnectorPeerPairRebindState](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RebindPublicURLConnectorPeerPair(ctx, publicURLID, pairID, body, editors...)
	})
}

func (c *Client) ListPublicURLConnectorPeerPairs(ctx context.Context, runID string, number uint64, after string, token credentials.PublishRunToken) (controlv1.ConnectorPeerPairCandidates, error) {
	if number == 0 || number > math.MaxInt64 || token == "" {
		return controlv1.ConnectorPeerPairCandidates{}, errors.New("invalid public URL connector publisher credentials")
	}
	params := &controlv1.ListPublicURLConnectorPeerPairsParams{PublishRunNumber: int64(number)}
	if after != "" {
		params.After = &after
	}
	return request[controlv1.ConnectorPeerPairCandidates](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListPublicURLConnectorPeerPairs(ctx, runID, params, editors...)
	})
}

func (c *Client) DeliverPublicURLConnectorPeerPair(ctx context.Context, runID string, number uint64, pairID string, generation int64, token credentials.PublishRunToken) (controlv1.PublicURLConnectorPeerPairDelivery, error) {
	if number == 0 || number > math.MaxInt64 || generation < 1 || token == "" {
		return controlv1.PublicURLConnectorPeerPairDelivery{}, errors.New("invalid public URL connector delivery request")
	}
	return request[controlv1.PublicURLConnectorPeerPairDelivery](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.DeliverPublicURLConnectorPeerPair(ctx, runID, pairID, controlv1.DeliverPublicURLConnectorPeerPairJSONRequestBody{
			PublishRunNumber: int64(number), DeliveryGeneration: generation}, editors...)
	})
}

func (c *Client) ConfirmPublicURLConnectorPeerPairPrepared(ctx context.Context, runID string, number uint64, pairID string, prepared controlv1.ConnectorPeerPairPrepared, token credentials.PublishRunToken) error {
	if number == 0 || number > math.MaxInt64 || token == "" {
		return errors.New("invalid public URL connector publisher credentials")
	}
	_, err := request[struct{}](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ConfirmPublicURLConnectorPeerPairPrepared(ctx, runID, pairID, controlv1.ConfirmPublicURLConnectorPeerPairPreparedJSONRequestBody{
			PublishRunNumber: int64(number), Prepared: prepared}, editors...)
	})
	return err
}
