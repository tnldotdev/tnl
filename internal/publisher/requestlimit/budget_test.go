package requestlimit

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestParseLimitsPreservesOmissionAndValidatesExplicitFields(t *testing.T) {
	for _, test := range []struct {
		name  string
		input *controlv1.ProjectHTTPApplicationLimits
		want  applicationlimits.Limits
	}{
		{name: "omitted"},
		{name: "empty", input: &controlv1.ProjectHTTPApplicationLimits{}},
		{name: "selected", input: &controlv1.ProjectHTTPApplicationLimits{Total: new(7), Concurrency: new(2),
			Rate: &controlv1.ProjectApplicationRate{Count: 3, Per: "4s", Burst: new(5)}},
			want: applicationlimits.Limits{Requests: 7, Concurrency: 2, RateRequests: 3, RatePer: 4 * time.Second, RateBurst: 5}},
		{name: "omitted burst", input: &controlv1.ProjectHTTPApplicationLimits{Rate: &controlv1.ProjectApplicationRate{Count: 3, Per: "4s"}},
			want: applicationlimits.Limits{RateRequests: 3, RatePer: 4 * time.Second}},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits, err := ParseLimits(test.input)
			if err != nil || limits != test.want {
				t.Fatal("wire parsing changed an explicit selection or applied defaults", limits, err)
			}
			budget, err := NewHTTP(test.input)
			if err != nil || budget.admission.Limits() != test.want.Defaults(false) {
				t.Fatal("HTTP admission did not use the shared parsed value", err)
			}
		})
	}
	for _, input := range []*controlv1.ProjectHTTPApplicationLimits{
		{Total: new(0)}, {Total: new(-1)}, {Concurrency: new(0)}, {Concurrency: new(-1)},
		{Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "bad"}},
		{Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "0s"}},
		{Rate: &controlv1.ProjectApplicationRate{Count: 0, Per: "1s"}},
		{Rate: &controlv1.ProjectApplicationRate{Count: 1}},
		{Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "1s", Burst: new(0)}},
		{Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "1s", Burst: new(-1)}},
	} {
		if _, err := ParseLimits(input); err == nil {
			t.Fatal("explicit nonpositive or invalid limit accepted", input)
		}
		if _, err := NewHTTP(input); err == nil {
			t.Fatal("HTTP admission bypassed wire validation", input)
		}
	}
}

func TestHTTPRejectionsKeepDiagnosticAndRetryContracts(t *testing.T) {
	for _, test := range []struct {
		name, code, retry string
		limits            controlv1.ProjectHTTPApplicationLimits
		finish            bool
		status            int
	}{
		{name: "concurrency", code: "TNL_REQUEST_LIMIT_REACHED", retry: "1",
			limits: controlv1.ProjectHTTPApplicationLimits{Concurrency: new(1)}, status: http.StatusServiceUnavailable},
		{name: "total", code: "TNL_REQUEST_BUDGET_EXHAUSTED",
			limits: controlv1.ProjectHTTPApplicationLimits{Total: new(1)}, finish: true, status: http.StatusServiceUnavailable},
		{name: "rate", code: "TNL_REQUEST_RATE_LIMITED", retry: "3600",
			limits: controlv1.ProjectHTTPApplicationLimits{Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "1h", Burst: new(1)}},
			finish: true, status: http.StatusTooManyRequests},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits, err := NewHTTP(&test.limits)
			if err != nil {
				t.Fatal(err)
			}
			first, ok := limits.Reserve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
			if !ok {
				t.Fatal("first request rejected")
			}
			defer first.Finish()
			if test.finish {
				first.Finish()
			}
			for _, version := range []int{1, 2} {
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					request := httptest.NewRequest(method, "/", nil)
					request.ProtoMajor = version
					request.Header.Set("Accept", "text/html")
					response := httptest.NewRecorder()
					if _, ok := limits.Reserve(response, request); ok {
						t.Fatal("exhausted budget admitted another request")
					}
					connection := ""
					if version == 1 {
						connection = "close"
					}
					if response.Code != test.status || response.Header().Get("Tnl-Error-Code") != test.code ||
						response.Header().Get("Retry-After") != test.retry || response.Header().Get("Connection") != connection ||
						response.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("request rejection changed its HTTP contract or closed HTTP/2 siblings", version, response.Code, response.Header())
					}
					if method == http.MethodHead && response.Body.Len() != 0 ||
						method == http.MethodGet && !strings.Contains(response.Body.String(), "<!doctype html>") {
						t.Fatal("request rejection lost HTML or HEAD negotiation", response.Body.String())
					}
				}
			}
		})
	}
}

func TestAdmissionBurstCancellationAndRefund(t *testing.T) {
	a, err := New(applicationlimits.Limits{Requests: 3, Concurrency: 1, RateRequests: 1, RatePer: time.Minute, RateBurst: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if release, status, _ := a.Acquire(ctx); release != nil || status == 0 || a.used != 0 || a.active != 0 {
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
	a.Refund()
	if status, _ := a.enter(now.Add(time.Minute)); status != 0 {
		t.Fatal("failed promotion spent a token or total")
	}
	a.leave()
	<-a.completed
	b, _ := New(applicationlimits.Limits{})
	release, status, _ := b.Acquire(t.Context())
	if status != 0 {
		t.Fatal(status)
	}
	release()
	release()
	if b.active != 0 {
		t.Fatal("duplicate cleanup released a different visitor's slot")
	}
}

func TestHTTPReservationRefundAndFinishAreExclusive(t *testing.T) {
	for _, refund := range []bool{false, true} {
		t.Run(map[bool]string{false: "finish", true: "refund"}[refund], func(t *testing.T) {
			limits, err := NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(1), Concurrency: new(1),
				Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "1h", Burst: new(1)}})
			if err != nil {
				t.Fatal(err)
			}
			reservation, ok := limits.Reserve(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
			if !ok {
				t.Fatal("initial reservation rejected")
			}
			if refund {
				reservation.Refund()
			} else {
				reservation.Finish()
			}
			var workers sync.WaitGroup
			for range 10 {
				workers.Go(reservation.Refund)
				workers.Go(reservation.Finish)
			}
			workers.Wait()
			if limits.admission.active != 0 {
				t.Fatal("cleanup released a slot twice")
			}
			select {
			case <-limits.Completed():
				if refund {
					t.Fatal("refund completed the application budget")
				}
			default:
				if !refund {
					t.Fatal("finish did not complete the application budget")
				}
			}
			next, ok := limits.Reserve(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
			if ok != refund {
				t.Fatal("refund did not restore total, concurrency, and rate together")
			}
			if ok {
				next.Finish()
				<-limits.Completed()
			}
		})
	}
}

func TestHTTPCompletionWaitsForEverySharedReservation(t *testing.T) {
	limits, err := NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(2)})
	if err != nil {
		t.Fatal(err)
	}
	first, ok := limits.Reserve(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if !ok {
		t.Fatal("first request rejected")
	}
	second, ok := limits.Reserve(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if !ok {
		t.Fatal("second request rejected")
	}
	rejected := httptest.NewRecorder()
	if _, ok := limits.Reserve(rejected, httptest.NewRequest("GET", "/", nil)); ok || rejected.Code != http.StatusServiceUnavailable {
		t.Fatal("exhausted total admitted another request")
	}
	first.Finish()
	select {
	case <-limits.Completed():
		t.Fatal("completed before the concurrent final request")
	default:
	}
	second.Finish()
	<-limits.Completed()
}

func TestHTTPReservationCancellationRacesFinishAndRefund(t *testing.T) {
	for range 100 {
		budget, err := New(applicationlimits.Limits{Requests: 1, Concurrency: 1, RateRequests: 1, RatePer: time.Hour, RateBurst: 1})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		reservation, status, _ := budget.Reserve(ctx)
		if status != 0 {
			t.Fatal(status)
		}
		var workers sync.WaitGroup
		workers.Go(cancel)
		workers.Go(reservation.Finish)
		workers.Go(reservation.Refund)
		workers.Wait()
		if budget.active != 0 || budget.used < 0 || budget.used > 1 {
			t.Fatal("racing cleanup corrupted another request's admission")
		}
		select {
		case <-budget.Completed():
			if budget.used != 1 {
				t.Fatal("refunded request completed the budget")
			}
		default:
			if budget.used != 0 || budget.tokens != 1 {
				t.Fatal("refunded request retained total or rate state")
			}
		}
	}
}

func TestApplicationAdmissionDrainsTotalBudgetWithoutCountingRejections(t *testing.T) {
	admission, err := New(applicationlimits.Limits{Requests: 2, Concurrency: 1})
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
	admission, err := New(applicationlimits.Limits{RateRequests: 2, RatePer: 4 * time.Second})
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

func TestExtremeRatePeriodRetryAfterDoesNotOverflow(t *testing.T) {
	a, err := New(applicationlimits.Limits{RateRequests: 1, RatePer: time.Duration(math.MaxInt64), RateBurst: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if status, _ := a.enter(now); status != 0 {
		t.Fatal(status)
	}
	a.leave()
	status, retry := a.enter(now)
	if status != 429 || retry != time.Duration(math.MaxInt64) || RetryAfterSeconds(retry) != 9223372037 {
		t.Fatalf("status=%d retry=%d seconds=%d", status, retry, RetryAfterSeconds(retry))
	}
	_, retry = a.enter(now.Add(time.Second))
	if retry < time.Duration(math.MaxInt64)-2*time.Second {
		t.Fatalf("overflow after partial refill: %s", retry)
	}
}
