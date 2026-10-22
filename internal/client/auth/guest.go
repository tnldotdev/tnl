package auth

import (
	"context"
	"errors"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
)

func RequireSignInOutsideDemo(ctx context.Context, state *clientstate.Database, serverURL, accessToken string) error {
	if accessToken != "" {
		return nil
	}
	store, err := state.Server(ctx, serverURL)
	if err != nil {
		return err
	}
	if _, found, err := store.ControlSession(ctx); err != nil || found {
		return err
	}
	if _, found, err := store.GuestSession(ctx); err != nil {
		return err
	} else if found {
		return failure.Wrap("use a signed-in command", failure.GuestSignInRequired,
			errors.New("saved guest credential does not authorize this command"))
	}
	return nil
}
