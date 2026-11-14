package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type changedPreparationControl struct {
	RunControl
	change func(*controlv1.ServiceRunPreparation)
}

func (c changedPreparationControl) PrepareServiceRun(ctx context.Context, service, key, access string, declaration controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	preparation, err := c.RunControl.PrepareServiceRun(ctx, service, key, access, declaration)
	if err == nil {
		c.change(&preparation)
	}
	return preparation, err
}

func TestServicePreparationIsValidatedBeforeLocalObservation(t *testing.T) {
	for _, boundary := range []string{"idempotency", "service", "run", "number", "hostname", "publisher", "expired", "traffic-missing", "traffic-invalid"} {
		t.Run(boundary, func(t *testing.T) {
			cfg, control := lifecycleFixture(t)
			cfg.Control = changedPreparationControl{RunControl: control, change: func(p *controlv1.ServiceRunPreparation) {
				switch boundary {
				case "idempotency":
					p.IdempotencyKey = "idem_" + strings.Repeat("I", 22)
				case "service":
					p.ServiceId = "svc_" + strings.Repeat("S", 22)
				case "number":
					p.RunNumber = 0
				case "run":
					p.ServiceRunId = ""
				case "hostname":
					p.Hostname = "other.example.test"
				case "publisher":
					p.PublisherIdentityId = "pub_" + strings.Repeat("P", 22)
				case "expired":
					p.ExpiresAt = time.Now()
				case "traffic-missing":
					p.Traffic = controlv1.TrafficLimits{}
				case "traffic-invalid":
					p.Traffic.RatePerNs = 0
				}
			}}
			observed := false
			cfg.Prepared = func(controlv1.ServiceRunPreparation) error { observed = true; return nil }
			if err := Publish(t.Context(), cfg); err == nil || observed || control.binds != 0 || control.closes != 0 {
				t.Fatal("unvalidated preparation reached local observation or run start", boundary, err, observed)
			}
		})
	}
}

func TestServicePreparationObserverFailureStopsBeforeRunStart(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	failure := errors.New("local observation failed")
	cfg.Prepared = func(p controlv1.ServiceRunPreparation) error {
		if p.ServiceId != cfg.ServiceID || p.ServiceRunId != control.prep.ServiceRunId || p.RunNumber != control.prep.RunNumber || p.Hostname != control.prep.Hostname {
			t.Error("local observation lost validated preparation facts")
		}
		return failure
	}
	if err := Publish(t.Context(), cfg); !errors.Is(err, failure) || control.prepares != 1 || control.binds != 0 || control.closes != 0 {
		t.Fatal("failed local observation started a run or lost its cause", err)
	}
}

func TestServicePreparationObservationIsNotRepeatedForUncertainStart(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	calls := 0
	cfg.Prepared = func(controlv1.ServiceRunPreparation) error { calls++; return nil }
	cfg.Connect = func(context.Context, *Bound, uint8, ConnectOptions) (SlotSession, error) {
		if calls != 1 {
			t.Error("connection started without one validated preparation observation")
		}
		return &heldSlot{stopped: make(chan struct{})}, nil
	}
	stop := errors.New("ready observation complete")
	cfg.Ready = func() error { return stop }
	if err := Publish(t.Context(), cfg); !errors.Is(err, stop) {
		t.Fatal("service run lost the owning observer result", err)
	}
	if calls != 1 || control.prepares != 1 || control.binds != 2 || control.closes != 1 {
		t.Fatal("uncertain run start duplicated preparation observation", calls, control.prepares, control.binds, control.closes)
	}
}
