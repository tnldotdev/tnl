package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/tnldotdev/tnl/internal/adhoc"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (a *appRuntime) publishAdHoc(ctx context.Context, request privateprotocol.AdHocRegister, update func(privateprotocol.AdHocStatus)) error {
	serverURL := request.ServerURL
	if serverURL == "" {
		serverURL = os.Getenv("TNL_SERVER")
	}
	if serverURL == "" {
		selected, found, err := a.state.SavedServer(ctx)
		if err != nil {
			return err
		}
		if found {
			serverURL = selected
		} else {
			serverURL = defaultServerURL
		}
	}
	serverURL, err := clientstate.CanonicalServer(serverURL)
	if err != nil {
		return err
	}
	profile, err := a.state.Server(ctx, serverURL)
	if err != nil {
		return err
	}
	limits := publisher.ApplicationLimits{}
	if request.Limits != nil {
		limits.Requests, limits.Concurrency = request.Limits.Requests, request.Limits.Concurrency
		if request.Limits.Rate != nil {
			limits.RateRequests = request.Limits.Rate.Requests
			limits.RatePer, err = time.ParseDuration(request.Limits.Rate.Per)
			if err != nil {
				return errors.New("invalid ad-hoc rate period")
			}
		}
	}
	if err := limits.Validate(); err != nil {
		return err
	}
	status := privateprotocol.AdHocStatus{Version: privateprotocol.Version, RegistrationID: request.RegistrationID, State: "starting"}
	return adhoc.Run(ctx, adhoc.Options{
		ControlURL: serverURL, State: profile, Credential: credentials.EphemeralCredential(request.Credential),
		InvocationID: request.RegistrationID, Target: request.Target,
		AllowIP: request.AllowIP, AllowAllIPs: request.AllowAllIPs, Limits: limits,
		OnAllocated: func(route controlv1.PublicURL) error {
			status.State, status.PublicURLID, status.PublicURL = "publishing", route.Id, "https://"+route.CanonicalHostname
			update(status)
			return nil
		},
		Observe: func(event publisher.Event) error {
			switch event.Type {
			case publisher.EventReady:
				if event.PublicURLID != status.PublicURLID || event.PublicURL != status.PublicURL {
					return errors.New("ready publish run does not match the ad-hoc allocation")
				}
				status.State, status.PublishRunNumber = "routable", event.PublishRunNumber
				update(status)
			case publisher.EventDraining:
				status.State = "draining"
				update(status)
			}
			return nil
		},
	})
}
