package privatepublisher

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type admissionControl struct {
	*lifecycleControl
	calls atomic.Int32
	err   error
}

func (c *admissionControl) AuthorizeServiceConnector(context.Context, string, string, credentials.PublishRunToken, controlv1.AuthorizeServiceConnectorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	call := c.calls.Add(1)
	if c.err != nil {
		return controlv1.ServiceClientCertificateDecision{}, c.err
	}
	return controlv1.ServiceClientCertificateDecision{Allowed: true, Admitted: call > 1, ValidUntil: time.Now().Add(time.Minute)}, nil
}

func TestConnectorAuthorizationWaitsForAdmissionAndPreservesInfrastructureCause(t *testing.T) {
	for _, infrastructureFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending-then-admitted", true: "infrastructure-failure"}[infrastructureFailure], func(t *testing.T) {
			cfg, control := lifecycleFixture(t)
			approved, err := control.GetPublisherPrivateService(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := newManagedPrepared(control.prep, approved, cfg)
			if err != nil {
				t.Fatal(err)
			}
			c := &admissionControl{lifecycleControl: control}
			cause := errors.New("fixture infrastructure cause")
			if infrastructureFailure {
				c.err = cause
			}
			_, cancel, err := configureManagedRun(t.Context(), cfg, prepared, control.setup, c, cfg.State)
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			visitor := prepared.managedVisitor(tunnelv1.PrivateForwardingHeader{PrivateStreamHeader: tunnelv1.PrivateStreamHeader{Connector: &tunnelv1.ConnectorAdmission{}}})
			connector := visitor.(publisher.ConnectorVisitor)
			decision, err := connector.Check(t.Context())
			if infrastructureFailure {
				if !errors.Is(err, cause) || decision.Allowed || c.calls.Load() != 1 {
					t.Fatal("infrastructure failure lost its cause or was admitted", decision, err)
				}
			} else if err != nil || !decision.Allowed || c.calls.Load() != 2 {
				t.Fatal("allowed pending authorization entered the target boundary", decision, err, c.calls.Load())
			}
		})
	}
}
