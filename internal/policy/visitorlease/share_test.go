package visitorlease

import (
	"bytes"
	"crypto/sha256"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestShareGuardTracksCurrentVerifierAcrossRevisionsAndClosesOnRevocation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, _ := fixture(t)
		id := "shr_" + strings.Repeat("A", 22)
		secret := bytes.Repeat([]byte{9}, 32)
		verifier := visitortoken.ShareVerifier{Digest: sha256.Sum256(secret), ExpiresAt: time.Now().Add(7 * 24 * time.Hour)}
		update.View = update.View.WithShareVerifiers(map[string]visitortoken.ShareVerifier{id: verifier})
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		token, _ := visitortoken.ShareToken(id, secret)
		view, _, _ := lease.Current()
		permission, err := visitortoken.VerifyBearer(token, view, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Int64
		guard, err := lease.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		for range 8 {
			time.Sleep(2 * time.Second)
			update.View.VisitorPolicyRevision++
			update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(visitortoken.PolicyLifetime)
			if err := lease.Apply(lease.Begin(), update); err != nil {
				t.Fatal(err)
			}
		}
		if stopped.Load() != 0 {
			t.Fatal("unrelated revisions canceled durable share")
		}
		update.View = update.View.WithShareVerifiers(nil)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		if stopped.Load() != 1 {
			t.Fatal("revocation retained active traffic")
		}
	})
}

func TestShareGuardStopsAtShortenedParentDeadlineAndPolicyOutage(t *testing.T) {
	for _, fault := range []string{"parent deadline", "policy outage"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lease, update, _ := fixture(t)
				id := "shr_" + strings.Repeat("A", 22)
				secret := bytes.Repeat([]byte{9}, 32)
				verifier := visitortoken.ShareVerifier{Digest: sha256.Sum256(secret), ExpiresAt: time.Now().Add(7 * 24 * time.Hour)}
				update.View = update.View.WithShareVerifiers(map[string]visitortoken.ShareVerifier{id: verifier})
				if err := lease.Apply(lease.Begin(), update); err != nil {
					t.Fatal(err)
				}
				token, _ := visitortoken.ShareToken(id, secret)
				view, _, _ := lease.Current()
				permission, err := visitortoken.VerifyBearer(token, view, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				var stopped atomic.Int64
				guard, err := lease.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
				if err != nil {
					t.Fatal(err)
				}
				defer guard.Close()
				deadline := view.ValidUntil
				if fault == "parent deadline" {
					deadline = time.Now().Add(time.Second)
					verifier.ExpiresAt = deadline
					update.View = update.View.WithShareVerifiers(map[string]visitortoken.ShareVerifier{id: verifier})
					if err := lease.Apply(lease.Begin(), update); err != nil {
						t.Fatal(err)
					}
				}
				time.Sleep(time.Until(deadline))
				synctest.Wait()
				if stopped.Load() != 1 {
					t.Fatal("active share outlived current authority")
				}
			})
		})
	}
}
