package controltest

import (
	"context"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

func SaveSession(ctx context.Context, client *clientstate.Database, origin string, session controlstate.ControlSession) error {
	store, err := client.Server(ctx, origin)
	if err != nil {
		return err
	}
	return store.SaveControlSession(ctx, clientstate.ControlSession{SessionID: session.SessionID, AccessToken: session.AccessToken.String(), RefreshToken: session.RefreshToken.String(), AccessExpiresAt: session.AccessExpiresAt, RefreshExpiresAt: session.RefreshExpiresAt})
}
