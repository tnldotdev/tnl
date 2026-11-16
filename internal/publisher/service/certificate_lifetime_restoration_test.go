package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceCertificatePlanAndPQMismatchesCloseExactPreparation(t *testing.T) {
	for _, boundary := range []string{"empty plan", "uncovered plan", "post quantum"} {
		t.Run(boundary, func(t *testing.T) {
			cfg, control := preparationCleanupFixture(t)
			cleanup := errors.New("independent invalid-certificate-preparation cleanup failure")
			control.cleanup = cleanup
			control.prepare = func(_ context.Context, _ int, p controlv1.ServiceRunPreparation) (controlv1.ServiceRunPreparation, error) {
				plan := *p.CertificatePlan
				plan.Identifiers = append([]string(nil), plan.Identifiers...)
				p.CertificatePlan = &plan
				switch boundary {
				case "empty plan":
					p.CertificatePlan = &controlv1.CertificatePlan{}
				case "uncovered plan":
					p.CertificatePlan.Identifiers = []string{"another.example.test"}
				case "post quantum":
					p.RequirePostQuantum = !p.RequirePostQuantum
				}
				return p, nil
			}
			observed, ready := false, false
			cfg.Prepared = func(controlv1.ServiceRunPreparation) error { observed = true; return nil }
			cfg.Ready = func() error { ready = true; return nil }
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err := Publish(ctx, cfg)
			if !errors.Is(err, ErrPrivateStream) || !errors.Is(err, cleanup) || observed || ready ||
				control.starts != 0 || control.heartbeats != 0 || control.installs != 0 || len(control.keys) != 1 {
				t.Fatal("invalid certificate plan or PQ response escaped validation or lost cleanup", err)
			}
			assertPreparationClosed(t, control)
		})
	}
}

func TestServicePreparedAuthorityCopiesCallerPlanAndToken(t *testing.T) {
	for _, mutation := range []string{"scalar authority", "plan fields", "plan identifiers"} {
		t.Run(mutation, func(t *testing.T) {
			cfg, control := lifecycleFixture(t)
			approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
			if err != nil {
				t.Fatal(err)
			}
			source := control.prep
			plan := *source.CertificatePlan
			plan.Identifiers = append([]string(nil), plan.Identifiers...)
			source.CertificatePlan = &plan
			wantPlan := plan
			wantPlan.Identifiers = append([]string(nil), plan.Identifiers...)
			want := source
			want.CertificatePlan = &wantPlan
			prepared, err := newManagedPrepared(source, approved, cfg)
			if err != nil {
				t.Fatal(err)
			}
			setup := control.setup
			bound, err := prepared.Activate(setup)
			if err != nil {
				t.Fatal(err)
			}
			defer bound.Invalidate()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			checked := &certificateRecoveryControl{lifecycleControl: control, store: cfg.State}
			maintain, closeRun, err := configureServiceRun(ctx, cfg, prepared, setup, checked, cfg.State, nil)
			if err != nil {
				t.Fatal(err)
			}
			done, joined := make(chan error, 1), make(chan struct{})
			started := false
			t.Cleanup(func() {
				cancel()
				if err := closeRun(); err != nil {
					t.Error("close copied-authority setup", err)
				}
				if started {
					<-joined
					if err := serviceWorkerError(<-done, context.Canceled); err != nil {
						t.Error("join copied-authority certificate worker", err)
					}
				}
			})
			switch mutation {
			case "scalar authority":
				source.ServiceId, source.ServiceRunId, source.RunToken = "another-service", "another-run", "another-token"
				source.RunNumber++
				setup.ServiceId, setup.ServiceRunId, setup.RunToken = "another-service", "another-run", "another-token"
				setup.RunNumber++
			case "plan fields":
				source.CertificatePlan.CacheKey, source.CertificatePlan.Scope = "another-cache", "another-scope"
			case "plan identifiers":
				source.CertificatePlan.Identifiers[0] = "another.example.test"
			}
			if !reflect.DeepEqual(prepared.Preparation, want) {
				t.Fatal("caller mutation changed the captured preparation, token, or certificate plan")
			}
			_, hello, err := bound.Hello(0)
			if err != nil || hello.ServiceConnection == nil || hello.ServiceConnection.ServiceID != want.ServiceId ||
				hello.ServiceConnection.ServiceRunID != want.ServiceRunId || hello.ServiceConnection.RunNumber != uint64(want.RunNumber) {
				t.Fatal("caller mutation changed bound relay authority", err)
			}
			started = true
			go func() { defer close(joined); done <- maintain() }()
			select {
			case <-prepared.certificateInstalled:
			case <-joined:
				t.Fatal("copied authority did not install its certificate")
			case <-ctx.Done():
				t.Fatal("copied authority did not acknowledge and install", context.Cause(ctx))
			}
			if _, err := control.HeartbeatServiceRun(ctx, prepared.Preparation.ServiceId, prepared.Preparation.ServiceRunId,
				credentials.ServiceRunToken(prepared.Preparation.RunToken), controlv1.ServiceRunHeartbeat{Healthy: true}); err != nil {
				t.Fatal("caller mutation changed heartbeat authority", err)
			}
			if _, err := prepared.currentCertificate(); err != nil {
				t.Fatal("copied approved plan did not retain serving material", err)
			}
			control.mu.Lock()
			bad, installs, heartbeats := control.bad, control.installs, control.heartbeats
			control.mu.Unlock()
			if bad != nil || installs != 1 || heartbeats != 1 {
				t.Fatal("copied authority mixed certificate acknowledgment or heartbeat credentials", bad, installs, heartbeats)
			}
			if text := fmt.Sprintf("%+v %#v %+v %#v", prepared, prepared, bound, bound); strings.Contains(text, want.RunToken) {
				t.Fatal("incidental preparation or bound formatting exposed the run token")
			}
		})
	}
}

func TestServicePendingRenewalLeavesDurableCurrentUntilExactExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		certificates, control, prepared := certificateRecoveryFixture(t)
		control.create = func(der []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
			return certificateFixtureIssuance(control.lifecycleControl, der, nil)
		}
		initial, err := certificates.advance(t.Context(), true)
		if err != nil {
			t.Fatal(err)
		}
		installed, polling := make(chan struct{}, 1), make(chan struct{}, 1)
		certificates.Install = func(certificate tls.Certificate) error {
			if err := prepared.installManagedCertificate(certificate); err != nil {
				return err
			}
			installed <- struct{}{}
			return nil
		}
		creates := 0
		control.create = func(der []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
			creates++
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				return controlv1.ServiceCertificateIssuance{}, err
			}
			if bytes.Equal(csr.RawSubjectPublicKeyInfo, initial.Certificate.Leaf.RawSubjectPublicKeyInfo) {
				t.Error("pending renewal reused the current certificate key")
			}
			return controlv1.ServiceCertificateIssuance{Id: "pending-durable-expiry",
				ServiceId: certificates.ServiceID, ServiceRunId: certificates.RunID, RunNumber: certificates.RunNumber,
				PublisherIdentityId: certificates.PublisherIdentityID, CertificatePlan: certificates.Plan,
				State: controlv1.CertificateIssuanceStatePending}, nil
		}
		pollFailure := errors.New("independent pending-renewal cleanup failure")
		control.get = func(ctx context.Context, id string) (controlv1.ServiceCertificateIssuance, error) {
			if id != "pending-durable-expiry" {
				t.Error("renewal changed the selected issuance")
			}
			polling <- struct{}{}
			<-ctx.Done()
			return controlv1.ServiceCertificateIssuance{}, errors.Join(context.Cause(ctx), pollFailure)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		done, joined := make(chan error, 1), make(chan struct{})
		collected := false
		t.Cleanup(func() {
			cancel()
			<-joined
			if !collected {
				if err := serviceWorkerError(<-done, context.Canceled); err != nil {
					t.Error("join pending-renewal worker", err)
				}
			}
		})
		go func() { defer close(joined); done <- certificates.Maintain(ctx) }()
		select {
		case <-installed:
		case <-joined:
			t.Fatal("certificate worker stopped before installing durable current material")
		case <-ctx.Done():
			t.Fatal("certificate worker did not install durable current material", context.Cause(ctx))
		}
		time.Sleep(time.Until(initial.RenewAt))
		select {
		case <-polling:
		case <-joined:
			t.Fatal("certificate worker stopped before pending renewal")
		case <-ctx.Done():
			t.Fatal("certificate worker did not reach pending renewal", context.Cause(ctx))
		}
		time.Sleep(time.Until(initial.Certificate.Leaf.NotAfter) - time.Second)
		serving, err := prepared.currentCertificate()
		if err != nil || !bytes.Equal(serving.Certificate[0], initial.Certificate.Certificate[0]) {
			t.Fatal("pending renewal displaced the live serving certificate", err)
		}
		reopened, err := control.store.CertificatesForPublisher(control.prep.TeamId, certificates.PublisherIdentityID, certificates.Plan)
		if err != nil {
			t.Fatal(err)
		}
		current, found, err := reopened.Current(t.Context(), certificates.Hostname)
		if err != nil || !found || current.IssuanceID != initial.IssuanceID ||
			!bytes.Equal(current.Certificate.Certificate[0], initial.Certificate.Certificate[0]) {
			t.Fatal("pending renewal displaced durable current material", found, err)
		}
		time.Sleep(time.Second)
		err = <-done
		collected = true
		<-joined
		if !errors.Is(err, errCertificateExpired) || !errors.Is(err, pollFailure) || creates != 1 {
			t.Fatal("renewal expiry lost its deadline, independent failure, or original workload", creates, err)
		}
		if _, err := prepared.currentCertificate(); !errors.Is(err, ErrPrivateStream) {
			t.Fatal("expired serving material remained available", err)
		}
		if _, _, err := reopened.Current(t.Context(), certificates.Hostname); !errors.Is(err, clientstate.ErrCertificateExpired) {
			t.Fatal("expired durable current material remained reusable", err)
		}
		lock, err := reopened.Lock(t.Context())
		if err != nil {
			t.Fatal("joined renewal retained its issuance lock", err)
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
	})
}
