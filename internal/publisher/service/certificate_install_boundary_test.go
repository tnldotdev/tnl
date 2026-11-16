package service

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestServiceCertificateInstallBoundary(t *testing.T) {
	for _, mode := range []string{
		"held_ack", "held_install", "install_failure", "promotion_failure",
		"cancel_held_install", "cancel_preserves_install_failure",
	} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				certificates, control, prepared := certificateRecoveryFixture(t)
				notifications := make(chan struct{}, 1)
				certificates.installed = notifications
				ctx, cancel := context.WithCancel(t.Context())
				ackEntered, allowACK := make(chan struct{}), make(chan struct{})
				installEntered, allowInstall := make(chan struct{}), make(chan struct{})
				joined := make(chan struct{})
				unblockACK := sync.OnceFunc(func() { close(allowACK) })
				unblockInstall := sync.OnceFunc(func() { close(allowInstall) })
				installFailure := errors.New("actual serving certificate installation failed")
				var result error
				acknowledgments, installs := 0, 0
				control.installed = func(issuance string, expires time.Time) error {
					close(ackEntered)
					select {
					case <-allowACK:
					case <-ctx.Done():
						return ctx.Err()
					}
					if err := control.lifecycleControl.MarkServiceCertificateInstalled(ctx,
						certificates.ServiceID, certificates.RunID, certificates.RunNumber,
						issuance, expires, certificates.Token); err != nil {
						return err
					}
					acknowledgments++
					if mode == "promotion_failure" {
						// replace only this fixture's pending record after ACK.
						// Maintain must surface the real Promote failure before Install.
						_, err := certificates.Cache.NewPending(ctx, certificates.Hostname)
						return err
					}
					return nil
				}
				certificates.Install = func(certificate tls.Certificate) error {
					installs++
					close(installEntered)
					select {
					case <-allowInstall:
					case <-ctx.Done():
						if mode == "cancel_preserves_install_failure" {
							return errors.Join(ctx.Err(), installFailure)
						}
						return ctx.Err()
					}
					if mode == "install_failure" {
						// reject through the real serving validator after the real
						// cache and ACK succeeded, rather than inventing an ACK failure.
						certificate.Certificate = nil
						if err := prepared.installManagedCertificate(certificate); err == nil {
							t.Error("real serving installation accepted missing certificate bytes")
						} else {
							return errors.Join(installFailure, err)
						}
					}
					err := prepared.installManagedCertificate(certificate)
					certificateInstallBoundaryRequireNoNotification(t, notifications, "before Install callback returns")
					return err
				}
				go func() {
					defer close(joined)
					result = certificates.Maintain(ctx)
				}()
				defer func() {
					cancel()
					// both callbacks honor cancellation; no test-only unblock is
					// needed for the real maintainer to join.
					synctest.Wait()
					certificateInstallBoundaryRequireClosed(t, joined, "certificate maintainer join")
					certificateInstallBoundaryRequireNoNotification(t, notifications, "after joined cleanup")
				}()
				synctest.Wait()
				certificateInstallBoundaryRequireClosed(t, ackEntered, "held certificate ACK")
				certificateInstallBoundaryRequireNoNotification(t, notifications, "while ACK is held")
				if installs != 0 || acknowledgments != 0 {
					t.Fatal("held ACK advanced actual installation", acknowledgments, installs)
				}
				if _, err := prepared.currentCertificate(); err == nil {
					t.Fatal("held ACK made serving material available")
				}
				if _, found, err := certificates.Cache.Current(ctx, certificates.Hostname); err != nil || found {
					t.Fatal("held ACK promoted durable current material", found, err)
				}
				if _, found, err := certificates.Cache.Staged(ctx, certificates.Hostname); err != nil || !found {
					t.Fatal("fixture did not stop after real staging and before promotion", found, err)
				}
				if mode == "held_ack" {
					cancel()
					synctest.Wait()
					certificateInstallBoundaryRequireClosed(t, joined, "held ACK cancellation")
					if !errors.Is(result, context.Canceled) || installs != 0 {
						t.Fatal("held ACK cancellation installed material or lost its cause", result, installs)
					}
					return
				}
				unblockACK()
				synctest.Wait()
				if mode == "promotion_failure" {
					certificateInstallBoundaryRequireClosed(t, joined, "failed promotion")
					if acknowledgments != 1 || installs != 0 || result == nil ||
						!strings.Contains(result.Error(), "acknowledged certificate does not match staged material") {
						t.Fatal("successful ACK hid real cache promotion failure", acknowledgments, installs, result)
					}
					certificateInstallBoundaryRequireNoNotification(t, notifications, "after real promotion failure")
					if _, err := prepared.currentCertificate(); err == nil {
						t.Fatal("failed promotion exposed serving material")
					}
					if _, found, err := certificates.Cache.Current(ctx, certificates.Hostname); err != nil || found {
						t.Fatal("failed promotion installed durable current material", found, err)
					}
					return
				}
				certificateInstallBoundaryRequireClosed(t, installEntered, "actual Install callback")
				certificateInstallBoundaryRequireNoNotification(t, notifications, "while actual Install is held after promotion")
				if acknowledgments != 1 || installs != 1 {
					t.Fatal("fixture did not separate successful ACK from held serving installation", acknowledgments, installs)
				}
				if _, found, err := certificates.Cache.Current(ctx, certificates.Hostname); err != nil || !found {
					t.Fatal("held serving installation did not follow real cache promotion", found, err)
				}
				if _, err := prepared.currentCertificate(); err == nil {
					t.Fatal("ACK and cache promotion alone exposed serving material")
				}
				select {
				case <-joined:
					t.Fatal("maintainer returned before its held Install callback completed", result)
				default:
				}
				if mode == "cancel_held_install" || mode == "cancel_preserves_install_failure" {
					cancel()
				} else {
					unblockInstall()
				}
				synctest.Wait()
				if mode == "held_install" {
					if _, err := prepared.currentCertificate(); err != nil {
						t.Fatal("successful real installation did not expose the serving certificate", err)
					}
					select {
					case <-notifications:
					default:
						t.Error("successful Install return did not notify the run owner")
					}
					certificateInstallBoundaryRequireNoNotification(t, notifications, "after consuming the successful installation notification")
					select {
					case <-joined:
						t.Fatal("maintainer stopped instead of owning subsequent renewal", result)
					default:
					}
					cancel()
					synctest.Wait()
				}
				certificateInstallBoundaryRequireClosed(t, joined, "installation completion or cancellation")
				if mode == "install_failure" {
					if !errors.Is(result, installFailure) || errors.Is(result, context.Canceled) {
						t.Fatal("actual installation failure was discarded or changed into cancellation", result)
					}
				} else if !errors.Is(result, context.Canceled) {
					t.Fatal("maintainer lost owner cancellation", result)
				}
				if mode == "cancel_preserves_install_failure" && !errors.Is(result, installFailure) {
					t.Fatal("cancellation discarded an independent Install failure", result)
				}
				if mode != "held_install" {
					certificateInstallBoundaryRequireNoNotification(t, notifications, "after failed or canceled actual Install")
					if _, err := prepared.currentCertificate(); err == nil {
						t.Fatal("failed or canceled installation became available to visitors")
					}
				}
			})
		})
	}
}

func TestServiceCertificateInstallBoundaryFullNotificationBuffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		certificates, _, prepared := certificateRecoveryFixture(t)
		notifications := make(chan struct{}, 1)
		notifications <- struct{}{}
		certificates.installed = notifications
		ctx, cancel := context.WithCancel(t.Context())
		joined := make(chan struct{})
		var result error
		go func() {
			defer close(joined)
			result = certificates.Maintain(ctx)
		}()
		defer func() {
			cancel()
			// release an incorrectly blocking send after a failed assertion too,
			// so the regression cannot leave a test-owned maintainer behind.
			select {
			case <-notifications:
			default:
			}
			synctest.Wait()
			certificateInstallBoundaryRequireClosed(t, joined, "full-buffer maintainer cleanup")
		}()
		synctest.Wait()
		if _, err := prepared.currentCertificate(); err != nil {
			t.Fatal("full notification buffer prevented real serving installation", err)
		}
		if len(notifications) != 1 {
			t.Error("installation replaced or consumed the pending notification")
		}
		cancel()
		synctest.Wait()
		certificateInstallBoundaryRequireClosed(t, joined, "cancellation with a full notification buffer")
		if !errors.Is(result, context.Canceled) {
			t.Error("coalesced notification lost maintainer cancellation", result)
		}
	})
}

func certificateInstallBoundaryRequireNoNotification(t *testing.T, notifications <-chan struct{}, boundary string) {
	t.Helper()
	select {
	case <-notifications:
		t.Error("installation notification arrived " + boundary)
	default:
	}
}

func certificateInstallBoundaryRequireClosed(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	default:
		t.Fatal(name + " did not reach its synchronized boundary")
	}
}
