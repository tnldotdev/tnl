package publisher

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type EventType string

const (
	EventPublicURLAssigned   EventType = "route" // preserve the existing internal event value.
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
	if config.Observe == nil {
		return nil
	}
	return config.Observe(event)
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
