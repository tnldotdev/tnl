package publisher

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestAdmissionBurstCancellationAndRefund(t *testing.T) {
	a, err := newApplicationAdmission(ApplicationLimits{Requests: 3, Concurrency: 1, RateRequests: 1, RatePer: time.Minute, RateBurst: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if release, status, _ := a.acquire(ctx); release != nil || status == 0 || a.used != 0 || a.active != 0 {
		t.Fatal("canceled admission spent a budget")
	}
	now := time.Now()
	for range 2 {
		if status, _ := a.enter(now); status != 0 {
			t.Fatal(status)
		}
		a.leave()
	}
	if status, _ := a.enter(now); status != http.StatusTooManyRequests {
		t.Fatal("burst did not cap initial tokens")
	}
	if status, _ := a.enter(now.Add(time.Minute)); status != 0 {
		t.Fatal("rate did not refill")
	}
	a.refund()
	if status, _ := a.enter(now.Add(time.Minute)); status != 0 {
		t.Fatal("failed promotion spent a token or total")
	}
	a.leave()
	<-a.completed
	b, _ := newApplicationAdmission(ApplicationLimits{})
	release, status, _ := b.acquire(t.Context())
	if status != 0 {
		t.Fatal(status)
	}
	release()
	release()
	if b.active != 0 {
		t.Fatal("duplicate cleanup released a different visitor's slot")
	}
}

func TestApplicationAdmissionDrainsTotalBudgetWithoutCountingRejections(t *testing.T) {
	admission, err := newApplicationAdmission(ApplicationLimits{Requests: 2, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if status, _ := admission.enter(now); status != 0 {
		t.Fatalf("first request rejected with %d", status)
	}
	if status, retry := admission.enter(now); status != http.StatusServiceUnavailable || retry != time.Second {
		t.Fatalf("concurrent request = %d, %s", status, retry)
	}
	admission.leave()
	select {
	case <-admission.completed:
		t.Fatal("concurrency rejection consumed the total budget")
	default:
	}
	if status, _ := admission.enter(now); status != 0 {
		t.Fatalf("second request rejected with %d", status)
	}
	if status, retry := admission.enter(now); status != http.StatusServiceUnavailable || retry != 0 {
		t.Fatalf("exhausted total budget = %d, %s", status, retry)
	}
	select {
	case <-admission.completed:
		t.Fatal("total budget finished before the active request drained")
	default:
	}
	admission.leave()
	select {
	case <-admission.completed:
	default:
		t.Fatal("total budget did not complete after the active request drained")
	}
}

func TestApplicationAdmissionRateRefillsEvenly(t *testing.T) {
	admission, err := newApplicationAdmission(ApplicationLimits{RateRequests: 2, RatePer: 4 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for range 2 {
		if status, _ := admission.enter(now); status != 0 {
			t.Fatalf("initial full bucket rejected with %d", status)
		}
		admission.leave()
	}
	if status, retry := admission.enter(now); status != http.StatusTooManyRequests || retry != 2*time.Second {
		t.Fatalf("empty bucket = %d, %s", status, retry)
	}
	if status, _ := admission.enter(now.Add(2 * time.Second)); status != 0 {
		t.Fatalf("half-period refill rejected with %d", status)
	}
	admission.leave()
	if status, retry := admission.enter(now.Add(3 * time.Second)); status != http.StatusTooManyRequests || retry < time.Second {
		t.Fatalf("one-second refill = %d, %s", status, retry)
	}
}
