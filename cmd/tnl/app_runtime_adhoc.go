package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/tnldotdev/tnl/internal/adhoc"
	"github.com/tnldotdev/tnl/internal/clientserver"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (a *appRuntime) publishAdHoc(ctx context.Context, request privateprotocol.AdHocRegister, update func(privateprotocol.AdHocStatus)) error {
	serverURL := request.ServerURL
	if serverURL == "" {
		serverURL = os.Getenv("TNL_SERVER")
	}
	serverURL, err := clientserver.Select(ctx, a.state, serverURL)
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
			limits.RateBurst = request.Limits.Rate.Burst
			limits.RatePer, err = time.ParseDuration(request.Limits.Rate.Per)
			if err != nil {
				return errors.New("invalid ad-hoc rate period")
			}
		}
	}
	if err := limits.Validate(); err != nil {
		return err
	}
	traffic := trafficlimits.Selection{}
	if request.Limits != nil && request.Limits.Traffic != nil {
		selected := request.Limits.Traffic
		if selected.Connections != 0 {
			traffic.Connections = &selected.Connections
		}
		if selected.Rate != nil {
			if selected.Rate.Count != 0 {
				traffic.Rate = &selected.Rate.Count
			}
			if selected.Rate.Per != "" {
				traffic.RatePer = &selected.Rate.Per
			}
			if selected.Rate.Burst != 0 {
				traffic.Burst = &selected.Rate.Burst
			}
		}
		if selected.Bandwidth != nil {
			if selected.Bandwidth.Upload != "" {
				rate, parseErr := trafficlimits.ParseByteRate(selected.Bandwidth.Upload)
				if parseErr != nil {
					return parseErr
				}
				traffic.UploadBytes = &rate
			}
			if selected.Bandwidth.Download != "" {
				rate, parseErr := trafficlimits.ParseByteRate(selected.Bandwidth.Download)
				if parseErr != nil {
					return parseErr
				}
				traffic.DownloadBytes = &rate
			}
		}
	}
	status := privateprotocol.AdHocStatus{Version: privateprotocol.Version, RegistrationID: request.RegistrationID, State: privateprotocol.AdHocStarting}
	return adhoc.Run(ctx, adhoc.Options{
		ControlURL: serverURL, State: profile, Credential: credentials.EphemeralCredential(request.Credential),
		InvocationID: request.RegistrationID, Target: request.Target,
		AllowIP: request.AllowIP, AllowAllIPs: request.AllowAllIPs, Limits: limits, Traffic: traffic,
		OnAllocated: func(route controlv1.PublicURL) error {
			status.State, status.PublicURLID, status.PublicURL = privateprotocol.AdHocPublishing, route.Id, "https://"+route.CanonicalHostname
			update(status)
			return nil
		},
		Observe: func(event publisher.Event) error {
			switch event.Type {
			case publisher.EventReady:
				if event.PublicURLID != status.PublicURLID || event.PublicURL != status.PublicURL {
					return errors.New("ready publish run does not match the ad-hoc allocation")
				}
				status.State, status.PublishRunNumber = privateprotocol.AdHocRoutable, event.PublishRunNumber
				update(status)
				if !a.noTelemetry && !request.TelemetryDisabled {
					queueSDKReady(ctx, a.state, request.RegistrationID, telemetryPublish, serverURL, "")
				}
			case publisher.EventDraining:
				status.State = privateprotocol.AdHocDraining
				update(status)
			}
			return nil
		},
	})
}
