package visitorlease

import (
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestUnchangedConfirmationCannotReviveOrReanchorPolicy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, _ := fixture(t)
		update.ConfirmationKey = strings.Repeat("1", 64)
		update.View.ValidUntil = time.Now().Add(12 * time.Second)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		first := lease.Begin()
		evidence := controlv1.PublisherPolicyConfirmation{ConfirmationKey: update.ConfirmationKey, Hostname: update.View.Hostname, ObservedAt: update.View.ObservedAt, ValidUntil: update.View.ValidUntil}
		time.Sleep(time.Second)
		refreshed := lease.Begin()
		if err := lease.Confirm(refreshed, evidence); err != nil {
			t.Fatal(err)
		}
		view, _, _ := lease.Current()
		if !view.ValidUntil.Equal(update.View.ValidUntil) {
			t.Fatal("replayed evidence moved the local deadline")
		}
		evidence.ObservedAt = time.Now()
		evidence.ValidUntil = evidence.ObservedAt.Add(time.Minute)
		if err := lease.Confirm(first, evidence); !errors.Is(err, ErrUpdate) {
			t.Fatal("older request replaced a newer observation", err)
		}
		inflight := lease.Begin()
		update.ConfirmationKey = strings.Repeat("2", 64)
		update.View.ObservedAt = time.Now()
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		if err := lease.Confirm(inflight, evidence); !errors.Is(err, ErrUpdate) {
			t.Fatal("old snapshot key extended new policy", err)
		}
		evidence.ConfirmationKey = update.ConfirmationKey
		pending := lease.Begin()
		time.Sleep(time.Until(update.View.ValidUntil))
		if err := lease.Confirm(pending, evidence); !errors.Is(err, ErrUpdate) {
			t.Fatal("expired policy was revived without a full snapshot", err)
		}
		if _, enabled, _ := lease.Current(); enabled {
			t.Fatal("failed confirmation left expired policy enabled")
		}
	})
}
