package controloutage

import (
	"errors"
	"testing"
	"time"
)

func TestServingConfirmationFreshSuccessExtendsWithoutRevisionChange(t *testing.T) {
	now := time.Now()
	observed := now.Add(time.Hour)
	first, err := (Confirmation{}).Confirm(now, observed, observed.Add(8*time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := first.Confirm(now.Add(2*time.Second), observed.Add(2*time.Second), observed.Add(10*time.Second), now.Add(3*time.Second))
	if err != nil || !next.Deadline.Equal(now.Add(10*time.Second)) {
		t.Fatal("fresh success did not extend from its own request start", next, err)
	}
	if _, err := next.Confirm(now.Add(4*time.Second), observed, observed.Add(time.Hour), now.Add(4*time.Second)); !errors.Is(err, ErrDeadline) {
		t.Fatal("older observation replaced current authority", err)
	}
}

func TestServingConfirmationRepeatedEvidenceAndEarlierExpiry(t *testing.T) {
	now := time.Now()
	first, err := (Confirmation{}).Confirm(now, now, now.Add(8*time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, until := range []time.Time{now.Add(8 * time.Second), now.Add(time.Hour)} {
		next, err := first.Confirm(now.Add(2*time.Second), now, until, now.Add(3*time.Second))
		if err != nil || !next.Deadline.Equal(first.Deadline) {
			t.Fatal("identical observation moved the clock", next, err)
		}
	}
	shorter, err := first.Confirm(now.Add(2*time.Second), now, now.Add(5*time.Second), now.Add(3*time.Second))
	if err != nil || !shorter.Deadline.Equal(now.Add(5*time.Second)) {
		t.Fatal("shorter absolute expiry was reanchored", shorter, err)
	}
	repeatedFixed, err := first.Confirm(now.Add(3*time.Second), now.Add(time.Second), now.Add(8*time.Second), now.Add(3*time.Second))
	if err != nil || !repeatedFixed.Deadline.Equal(first.Deadline) {
		t.Fatal("repeated absolute expiry was extended", repeatedFixed, err)
	}
}

func TestServingConfirmationLateSuccessCannotReviveExpiredOwner(t *testing.T) {
	now := time.Now()
	first, err := (Confirmation{}).Confirm(now, now, now.Add(3*time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Duration{3 * time.Second, 4 * time.Second} {
		if _, err := first.Confirm(now.Add(time.Second), now.Add(time.Second), now.Add(time.Minute), now.Add(at)); !errors.Is(err, ErrDeadline) {
			t.Fatal("late reply revived an expired owner", err)
		}
	}
	// recovery can authorize a new owner; it cannot reuse the expired admission.
	if _, err := (Confirmation{}).Confirm(now.Add(4*time.Second), now.Add(4*time.Second), now.Add(time.Minute), now.Add(4*time.Second)); err != nil {
		t.Fatal("fresh owner could not obtain new permission", err)
	}
}
