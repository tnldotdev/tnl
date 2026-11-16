package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceCertificateExpiryInterruptsBlockedRenewal(t *testing.T) {
	for _, mode := range []string{"pending", "blocked-poll", "blocked-poll-failure", "cache-lock"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				certificates, control, prepared := certificateRecoveryFixture(t)
				initial, err := certificates.advance(t.Context(), true)
				if err != nil {
					t.Fatal(err)
				}
				installed := make(chan struct{}, 1)
				certificates.Install = func(certificate tls.Certificate) error {
					if err := prepared.installManagedCertificate(certificate); err != nil {
						return err
					}
					select {
					case installed <- struct{}{}:
					default:
					}
					return nil
				}
				calls := 0
				pending := controlv1.ServiceCertificateIssuance{Id: "pending-renewal", ServiceId: certificates.ServiceID,
					ServiceRunId: certificates.RunID, RunNumber: certificates.RunNumber, PublisherIdentityId: certificates.PublisherIdentityID,
					CertificatePlan: certificates.Plan, State: controlv1.CertificateIssuanceStatePending}
				control.create = func([]byte, string) (controlv1.ServiceCertificateIssuance, error) {
					calls++
					return pending, nil
				}
				polling := make(chan struct{}, 1)
				pollFailure := errors.New("independent certificate poll cleanup failed")
				control.get = func(ctx context.Context, id string) (controlv1.ServiceCertificateIssuance, error) {
					if id != pending.Id {
						t.Error("renewal polled a different issuance")
					}
					select {
					case polling <- struct{}{}:
					default:
					}
					if mode == "blocked-poll" || mode == "blocked-poll-failure" {
						<-ctx.Done()
						if mode == "blocked-poll-failure" {
							return controlv1.ServiceCertificateIssuance{}, errors.Join(ctx.Err(), pollFailure)
						}
						return controlv1.ServiceCertificateIssuance{}, ctx.Err()
					}
					return pending, nil
				}
				ctx, cancel := context.WithCancel(t.Context())
				done, joined := make(chan error, 1), make(chan struct{})
				go func() { defer close(joined); done <- certificates.Maintain(ctx) }()
				defer func() { cancel(); <-joined }()
				<-installed
				var lock *clientstate.Lock
				if mode == "cache-lock" {
					lock, err = certificates.Cache.Lock(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					defer lock.Close()
				}
				time.Sleep(time.Until(initial.RenewAt) + time.Second)
				synctest.Wait()
				if mode != "cache-lock" {
					select {
					case <-polling:
					default:
						t.Fatal("renewal did not reach its pending polling boundary")
					}
				}
				time.Sleep(time.Until(initial.Certificate.Leaf.NotAfter) - time.Second)
				synctest.Wait()
				if _, err := prepared.currentCertificate(); err != nil {
					t.Fatal("blocked renewal retired the still-valid serving certificate", err)
				}
				select {
				case err := <-done:
					t.Fatal("certificate worker ended before the installed certificate expired", err)
				default:
				}
				time.Sleep(time.Second)
				synctest.Wait()
				select {
				case err := <-done:
					if !errors.Is(err, errCertificateExpired) {
						t.Fatal("renewal did not retain the local certificate-expiry cause", err)
					}
					if mode == "blocked-poll-failure" && !errors.Is(err, pollFailure) {
						t.Fatal("certificate expiry hid an independent poll cleanup failure", err)
					}
				default:
					t.Fatal("certificate worker survived expiry while renewal was blocked")
				}
				if _, err := prepared.currentCertificate(); err == nil {
					t.Fatal("expired serving certificate remained available")
				}
				if mode == "cache-lock" {
					if calls != 0 {
						t.Fatal("expired renewal issued after its cache lock", calls)
					}
					if err := lock.Close(); err != nil {
						t.Fatal(err)
					}
				}
				lock, err = certificates.Cache.Lock(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				_ = lock.Close()
			})
		})
	}
}

func TestServiceCertificateCurrentMaterialDoesNotWaitForIssuanceLock(t *testing.T) {
	certificates, _, _ := certificateRecoveryFixture(t)
	initial, err := certificates.advance(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := certificates.Cache.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	material, err := certificates.advance(ctx, true)
	if err != nil || material.IssuanceID != initial.IssuanceID {
		t.Fatal("current acknowledged material waited for another renewal's issuance lock", err)
	}
}

func TestServiceCertificateRenewalReplacesTheServingExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		certificates, control, prepared := certificateRecoveryFixture(t)
		control.create = func(csr []byte, key string) (controlv1.ServiceCertificateIssuance, error) {
			issued, err := certificateFixtureIssuance(control.lifecycleControl, csr, nil)
			issued.Id = "renewal-" + key
			return issued, err
		}
		installed := make(chan tls.Certificate, 2)
		certificates.Install = func(certificate tls.Certificate) error {
			if err := prepared.installManagedCertificate(certificate); err != nil {
				return err
			}
			installed <- certificate
			return nil
		}
		ctx, cancel := context.WithCancel(t.Context())
		joined, done := make(chan struct{}), make(chan error, 1)
		go func() { defer close(joined); done <- certificates.Maintain(ctx) }()
		defer func() {
			cancel()
			<-joined
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Error("certificate renewal lost its owner cancellation", err)
			}
		}()
		first := <-installed
		current, found, err := certificates.Cache.Current(t.Context(), certificates.Hostname)
		if err != nil || !found {
			t.Fatal("initial certificate did not become durable current material", found, err)
		}
		time.Sleep(time.Until(current.RenewAt))
		second := <-installed
		if !second.Leaf.NotAfter.After(first.Leaf.NotAfter) ||
			bytes.Equal(second.Leaf.RawSubjectPublicKeyInfo, first.Leaf.RawSubjectPublicKeyInfo) {
			t.Fatal("renewal failed to replace the certificate key and expiry")
		}
		time.Sleep(time.Until(first.Leaf.NotAfter) + time.Second)
		synctest.Wait()
		select {
		case <-joined:
			t.Fatal("the replaced certificate's old expiry stopped renewal")
		default:
		}
		serving, err := prepared.currentCertificate()
		if err != nil || !bytes.Equal(serving.Certificate[0], second.Certificate[0]) {
			t.Fatal("the replaced certificate's old expiry retired its successor", err)
		}
	})
}

func TestServiceCertificateRenewalRechecksExpiryAfterCacheLock(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_expiry", true: "at_expiry"}[expired], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				certificates, control, prepared := certificateRecoveryFixture(t)
				control.create = func(csr []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
					return certificateFixtureIssuance(control.lifecycleControl, csr, nil)
				}
				initial, err := certificates.advance(t.Context(), true)
				if err != nil {
					t.Fatal(err)
				}
				lock, err := certificates.Cache.Lock(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				installed := make(chan struct{}, 1)
				certificates.Install = func(certificate tls.Certificate) error {
					if err := prepared.installManagedCertificate(certificate); err != nil {
						return err
					}
					installed <- struct{}{}
					return nil
				}
				creates := 0
				control.create = func([]byte, string) (controlv1.ServiceCertificateIssuance, error) {
					creates++
					return controlv1.ServiceCertificateIssuance{}, clientcontrol.ErrStatusConflict
				}
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
				defer cancel()
				done, joined := make(chan error, 1), make(chan struct{})
				go func() { defer close(joined); done <- certificates.Maintain(ctx) }()
				defer func() { cancel(); <-joined }()
				// an initial cache acknowledgment bypasses the held issuance lock.
				<-installed
				time.Sleep(time.Until(initial.RenewAt))
				synctest.Wait()
				if expired {
					time.Sleep(time.Until(initial.Certificate.Leaf.NotAfter))
					synctest.Wait()
				}
				if err := lock.Close(); err != nil {
					t.Fatal(err)
				}
				err = <-done
				if expired {
					if creates != 0 || !errors.Is(err, errCertificateExpired) {
						t.Fatal("expired renewal crossed its cache lock", creates, err)
					}
				} else if creates != 1 || !errors.Is(err, clientcontrol.ErrStatusConflict) {
					t.Fatal("valid renewal failed to advance after its cache lock", creates, err)
				}
			})
		})
	}
}
