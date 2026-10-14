package publisher

import (
	"net/http"
	"testing"
	"time"
)

func TestApplicationAdmissionDrainsTotalBudgetWithoutCountingRejections(t *testing.T) {
	admission, err := newApplicationAdmission(ApplicationLimits{Requests: 2, Concurrency: 1}, false)
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
	admission, err := newApplicationAdmission(ApplicationLimits{RateRequests: 2, RatePer: 4 * time.Second}, false)
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

func TestApplicationAdmissionBurstAndProtocolDefaults(t *testing.T) {
	for _, test := range []struct {
		tcp                      bool
		concurrency, rate, burst int
	}{{false, 64, 60, 60}, {true, 24, 10, 20}} {
		admission, err := newApplicationAdmission(ApplicationLimits{}, test.tcp)
		if err != nil || admission.limits.Concurrency != test.concurrency || admission.limits.RateRequests != test.rate || admission.limits.RateBurst != test.burst || admission.limits.RatePer != time.Second {
			t.Fatalf("TCP=%t defaults = %+v, %v", test.tcp, admission, err)
		}
	}
	admission, err := newApplicationAdmission(ApplicationLimits{RateRequests: 1, RatePer: time.Second, RateBurst: 3}, false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for range 3 {
		if status, _ := admission.enter(now); status != 0 {
			t.Fatalf("permitted burst request rejected with %d", status)
		}
		admission.leave()
	}
	if status, _ := admission.enter(now); status != http.StatusTooManyRequests {
		t.Fatalf("burst exhaustion = %d", status)
	}
	if status, _ := admission.enter(now.Add(time.Second)); status != 0 {
		t.Fatalf("rate did not refill after burst: %d", status)
	}
	admission.leave()
	for _, limits := range []ApplicationLimits{{RateBurst: 1}, {RateBurst: -1}} {
		if _, err := newApplicationAdmission(limits, false); err == nil {
			t.Fatalf("accepted invalid burst: %+v", limits)
		}
	}
}
