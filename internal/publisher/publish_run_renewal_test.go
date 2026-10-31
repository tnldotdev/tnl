package publisher

import (
	"crypto/x509"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestCertificateRenewalRechecksExpiryAfterCacheLock(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "before_expiry"
		if expired {
			name = "at_expiry"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				control, route, state := newCertificateTransactionTest(t)
				control.change = func(issuance *controlv1.CertificateIssuance, leaf *x509.Certificate) {
					leaf.NotAfter = time.Now().Add(90 * time.Second)
					issuance.NotAfter = pointer(leaf.NotAfter)
				}
				authority := testRunAuthority(t, control, control.setup)
				material, err := attemptCertificateTransaction(t.Context(), authority, route, state, false)
				if err != nil {
					t.Fatal(err)
				}
				lock, err := state.Lock(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				calls := 0
				control.create = func([]byte, string) (controlv1.CertificateIssuance, error) {
					calls++
					return controlv1.CertificateIssuance{}, clientcontrol.ErrStatusConflict
				}
				done := make(chan error, 1)
				go func() { done <- runCertificateRenewals(t.Context(), Config{}, authority, route, state, material) }()
				time.Sleep(time.Until(material.RenewAt))
				synctest.Wait()
				if expired {
					time.Sleep(time.Until(material.Certificate.Leaf.NotAfter))
					synctest.Wait()
				}
				if err := lock.Close(); err != nil {
					t.Fatal(err)
				}
				err = <-done
				if expired {
					if calls != 0 || !errors.Is(err, errCertificateExpired) {
						t.Fatalf("expired renewal crossed cache lock: requests=%d error=%v", calls, err)
					}
				} else if calls != 1 || !errors.Is(err, clientcontrol.ErrStatusConflict) {
					t.Fatalf("valid renewal did not advance: requests=%d error=%v", calls, err)
				}
			})
		})
	}
}
