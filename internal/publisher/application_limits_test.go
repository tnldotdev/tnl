package publisher

import (
	"net/http"
	"testing"
	"time"
)

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
