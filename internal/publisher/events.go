package publisher

import (
	"context"
	"time"

	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type EventType string

const (
	EventPublicURLAssigned   EventType = "public_url_assigned"
	EventProvisioning        EventType = "provisioning"
	EventProvisioningStep    EventType = "provisioning_step"
	EventProvisioningStalled EventType = "provisioning_stalled"
	EventReady               EventType = "ready"
	EventDraining            EventType = "draining"
	EventTransportFallback   EventType = "transport_fallback"
	EventTargetUnavailable   EventType = "target_unavailable"
)

type Event struct {
	Type              EventType
	PublicURLID       string
	Hostname          string
	PublicURL         string
	PublishRunNumber  uint64
	ProvisioningStage string
	Transport         tunnel.Transport
}

func observe(config Config, event Event) error {
	if config.Observe != nil {
		if err := config.Observe(event); err != nil {
			return err
		}
	}
	if event.Type == EventReady && (config.Purpose == "" || config.Purpose == controlv1.App || config.Purpose == controlv1.Demo) {
		payload := telemetryv1.PublicationReady{ServerKind: telemetryv1.SelfHosted, PublishMode: telemetryv1.App}
		if config.ControlURL == clientserver.DefaultURL {
			payload.ServerKind = telemetryv1.Hosted
		}
		if config.Demo {
			payload.PublishMode = telemetryv1.Demo
		}
		if config.TelemetryFramework != "" {
			payload.Framework = &config.TelemetryFramework
		}
		config.telemetry.Ready(payload)
	}
	return nil
}

func observeProvisioningStall(ctx context.Context, config Config, setup controlv1.PublishRunSetup) error {
	timer := time.NewTimer(config.ProvisioningStalledDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-timer.C:
		return observe(config, Event{
			Type: EventProvisioningStalled, PublicURLID: setup.PublicUrl.Id, Hostname: setup.PublicUrl.CanonicalHostname,
			PublishRunNumber: uint64(setup.PublishRun.PublishRunNumber),
		})
	}
}
