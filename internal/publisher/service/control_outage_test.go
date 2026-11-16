package service

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/controloutage"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestRunServingConfirmationSpendsLatencyAndRejectsExpiredReply(t *testing.T) {
	started := time.Now()
	wire := controlv1.ServiceRunState{ObservedAt: started.Add(time.Hour), PublisherExpiresAt: started.Add(time.Hour + 5*time.Second)}
	accepted, state, err := acceptServingConfirmation(controloutage.Confirmation{}, started, wire, started.Add(time.Second))
	if err != nil || !state.PublisherExpiresAt.Equal(started.Add(5*time.Second)) || !wire.PublisherExpiresAt.Equal(started.Add(time.Hour+5*time.Second)) {
		t.Fatal("run deadline used control clock or reply arrival", state, err)
	}
	wire.ObservedAt = wire.ObservedAt.Add(time.Second)
	wire.PublisherExpiresAt = wire.PublisherExpiresAt.Add(time.Minute)
	if _, _, err := acceptServingConfirmation(accepted, started.Add(time.Second), wire, started.Add(5*time.Second)); !errors.Is(err, controloutage.ErrDeadline) {
		t.Fatal("late heartbeat revived the expired run", err)
	}
}
