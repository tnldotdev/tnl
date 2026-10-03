package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func guestForDemo(
	ctx context.Context, state *clientstate.Database, serverURL string, flags publishCommand,
) (*clientstate.GuestSession, error) {
	control, err := controlclient.New(serverURL, nil, "")
	if err != nil {
		return nil, err
	}
	return guestForDemoWithControl(ctx, state, serverURL, flags, control)
}

type guestDemoControlClient interface {
	Discovery(context.Context) (controlv1.ControlDiscovery, error)
	CreateGuestDemo(context.Context) (controlv1.GuestDemoSession, error)
}

func guestForDemoWithControl(
	ctx context.Context, state *clientstate.Database, serverURL string, flags publishCommand,
	control guestDemoControlClient,
) (*clientstate.GuestSession, error) {
	if flags.AccessToken != "" {
		return nil, nil
	}
	store, err := state.Server(ctx, serverURL)
	if err != nil {
		return nil, err
	}
	lock, err := clientstate.LockGuestSessionContext(ctx, store)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if _, found, err := store.ControlSession(ctx); err != nil || found {
		return nil, err
	}
	discovery, err := control.Discovery(ctx)
	if err != nil || !discovery.GuestDemoEnabled {
		return nil, err
	}
	if flags.Team != "" || flags.Domain != "" || flags.AllowAllIPs || len(flags.AllowIP) != 0 ||
		len(flags.AllowProvider) != 0 {
		return nil, errors.New("guest demos use your current IP and assigned namespace; run tnl login to change these settings")
	}
	guest, found, err := store.GuestSession(ctx)
	if err != nil {
		return nil, err
	}
	if found && !guest.ExpiresAt.After(time.Now()) {
		if err := store.RemoveGuestSession(ctx); err != nil {
			return nil, err
		}
		found = false
	}
	if !found {
		issued, err := control.CreateGuestDemo(ctx)
		if err != nil {
			return nil, fmt.Errorf("start guest demo: %w", err)
		}
		guest = clientstate.GuestSession{
			GuestID: issued.GuestId, AccessToken: issued.AccessToken, TeamID: issued.TeamId,
			MembershipID: issued.MembershipId, DomainID: issued.DomainId,
			Namespace: issued.Namespace,
			ExpiresAt: issued.ExpiresAt,
		}
		if err := store.SaveGuestSession(ctx, guest); err != nil {
			return nil, err
		}
	}
	return &guest, nil
}

func requireSignInOutsideDemo(ctx context.Context, state *clientstate.Database, serverURL, accessToken string) error {
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
		return errors.New("this command needs sign-in. run `tnl login` to use your own app or manage this server; to try tnl without sign-in, run `tnl publish --demo`")
	}
	return nil
}

func guestPublisherServices(
	ctx context.Context, state *clientstate.Database, serverURL, hostname string,
	guest clientstate.GuestSession, routes *controlclient.Client,
) (publisherServices, error) {
	store, err := state.Server(ctx, serverURL)
	if err != nil {
		return publisherServices{}, err
	}
	return publisherServices{
		state: store, hostname: hostname + "." + guest.Namespace, namespace: guest.Namespace,
		teamID: guest.TeamID, membershipID: guest.MembershipID, domainID: guest.DomainID,
		publicURLScope: controlv1.Member, policyRevision: 1, ephemeral: true, routes: routes,
	}, nil
}
