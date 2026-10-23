package service

import (
	"context"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type admissionControl struct {
	*lifecycleControl
	calls atomic.Int32
	err   error
}

func (c *admissionControl) AuthorizeServiceClientCertificate(context.Context, string, string, credentials.ServiceRunToken, controlv1.AuthorizeServiceClientCertificateRequest) (controlv1.ServiceClientCertificateDecision, error) {
	call := c.calls.Add(1)
	if c.err != nil {
		return controlv1.ServiceClientCertificateDecision{}, c.err
	}
	return controlv1.ServiceClientCertificateDecision{Allowed: true, Admitted: call > 1, ValidUntil: time.Now().Add(time.Minute)}, nil
}

func TestCertificateAuthorizationWaitsForAdmissionAndPreservesInfrastructureCause(t *testing.T) {
	for _, infrastructureFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending-then-admitted", true: "infrastructure-failure"}[infrastructureFailure], func(t *testing.T) {
			cfg, control := lifecycleFixture(t)
			approved, err := control.GetPublisherService(t.Context(), "")
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
			_, cancel, err := configureServiceRun(t.Context(), cfg, prepared, control.setup, c, cfg.State)
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			visitor := prepared.managedVisitor(tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{Direct: &tunnelv1.DirectAdmission{}}})
			certificate := visitor.(publisher.CertificateVisitor)
			decision, err := certificate.Check(t.Context(), &x509.Certificate{})
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
