package httpprotection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"testing/synctest"
	"time"

	policy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
)

var eligibleRejection = Result{Status: 403, RuleIDs: []int{941100, 942100}}

func TestTemporaryBlocksPrepareOnlyWithExplicitReportingAuthority(t *testing.T) {
	for _, settings := range []policy.Settings{{}, {WAF: policy.Detect, TemporaryBlocks: true}, {WAF: policy.Off, TemporaryBlocks: true}} {
		p, err := Prepare(t.Context(), settings, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.blocks != nil {
			t.Fatal("disabled source blocking started a worker")
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Prepare(t.Context(), policy.Settings{TemporaryBlocks: true}, nil, nil); err == nil {
		t.Fatal("source blocking prepared without current run authority")
	}
}

func TestTemporaryBlocksHandlerCountsRejectionsFromTrustedMetadata(t *testing.T) {
	reports := make(chan policy.Rejections, 1)
	p, err := Prepare(t.Context(), policy.Settings{TemporaryBlocks: true}, func(_ context.Context, r policy.Rejections) error { reports <- r; return nil }, func(netip.Addr, time.Time) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	}()
	forwarded := 0
	h := p.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded++; w.WriteHeader(204) }), nil)
	request := func(source, query string) int {
		r := httptest.NewRequest("GET", "https://app.example/"+query, nil)
		r.RemoteAddr = source
		r.Header.Set("X-Forwarded-For", "203.0.113.20")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for range policy.BlockThreshold {
		if status := request("192.0.2.1:2345", "?q="+url.QueryEscape("<script>alert(1)</script>")); status != 403 {
			t.Fatal("eligible attack was not rejected", status)
		}
	}
	select {
	case evidence := <-reports:
		if evidence.SourceIP != "192.0.2.1" || evidence.Validate(time.Now()) != nil {
			t.Fatal("report trusted a forwarding header or lost its fixed evidence", evidence)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("threshold report did not reach the bounded worker")
	}
	if status := request("192.0.2.1:3456", ""); status != 403 || forwarded != 0 {
		t.Fatal("benign request on an existing blocked connection reached the application")
	}
	if status := request("192.0.2.2:3456", ""); status != 204 || forwarded != 1 {
		t.Fatal("block expanded to another source", status)
	}
}

func TestTemporaryBlocksCountRequestsAndRequireFreshEvidence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reports := make(chan policy.Rejections, 2)
		b := newTemporaryBlocks(t.Context(), func(_ context.Context, r policy.Rejections) error { reports <- r; return nil }, nil)
		defer b.close()
		source := netip.MustParseAddr("192.0.2.1")
		for range policy.BlockThreshold - 1 {
			b.reject(source, eligibleRejection, time.Now())
		}
		if b.blocked(source, time.Now()) || len(b.queue) != 0 {
			t.Fatal("rule matches were counted instead of rejected requests")
		}
		b.reject(source, eligibleRejection, time.Now())
		report := <-reports
		if err := report.Validate(time.Now()); err != nil || !b.blocked(source, time.Now()) {
			t.Fatal("threshold did not block exact source", err)
		}
		for range policy.BlockThreshold * 2 {
			b.reject(source, eligibleRejection, time.Now())
		}
		synctest.Wait()
		if len(reports) != 0 {
			t.Fatal("existing block produced another report")
		}
		time.Sleep(policy.BlockDuration)
		if b.blocked(source, time.Now()) {
			t.Fatal("expired local block remained active")
		}
		for range policy.BlockThreshold - 1 {
			b.reject(source, eligibleRejection, time.Now())
		}
		if b.blocked(source, time.Now()) {
			t.Fatal("rejections during the block counted toward its replacement")
		}
		b.reject(source, eligibleRejection, time.Now())
		next := <-reports
		if !next.StartedAt.After(report.EndedAt) || !b.blocked(source, time.Now()) {
			t.Fatal("replacement did not require fresh evidence")
		}
	})
}

func TestTemporaryBlocksExcludeIneligibleFailuresAndKeepExactIPs(t *testing.T) {
	b := newTemporaryBlocks(t.Context(), func(context.Context, policy.Rejections) error { return nil }, nil)
	defer b.close()
	now := time.Now()
	v4 := netip.MustParseAddr("192.0.2.1")
	for _, result := range []Result{
		{RuleIDs: []int{942100}}, {Status: 400, RuleIDs: []int{942100}},
		{Status: 413}, {Status: 415}, {Status: 503},
		{Status: 403}, {Status: 403, RuleIDs: []int{920420, 949110}},
	} {
		for range policy.BlockThreshold {
			b.reject(v4, result, now)
		}
	}
	if len(b.sources) != 0 {
		t.Fatal("ordinary policy or safety failures created source counters")
	}
	for _, source := range []netip.Addr{v4, netip.MustParseAddr("2001:db8::1")} {
		for range policy.BlockThreshold {
			b.reject(source, eligibleRejection, now)
		}
		if !b.blocked(source, now) {
			t.Fatal("exact source did not block")
		}
	}
	if b.blocked(netip.MustParseAddr("192.0.2.2"), now) || b.blocked(netip.MustParseAddr("2001:db8::2"), now) {
		t.Fatal("block expanded to a neighboring IP or IPv6 /64")
	}
	if !b.blocked(netip.MustParseAddr("::ffff:192.0.2.1"), now) {
		t.Fatal("mapped IPv4 source escaped its exact IP block")
	}
}

func TestTemporaryBlockReportingNeverWaitsAndJoinsCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{})
		b := newTemporaryBlocks(t.Context(), func(ctx context.Context, _ policy.Rejections) error {
			select {
			case <-started:
			default:
				close(started)
			}
			<-ctx.Done()
			return ctx.Err()
		}, nil)
		defer b.close()
		for range policy.BlockThreshold {
			b.reject(netip.AddrFrom4([4]byte{192, 0, 2, 0}), eligibleRejection, time.Now())
		}
		<-started
		for n := 1; n < 80; n++ {
			source := netip.AddrFrom4([4]byte{192, 0, 2, byte(n)})
			for range policy.BlockThreshold {
				b.reject(source, eligibleRejection, time.Now())
			}
		}
		if len(b.queue) != cap(b.queue) || len(b.sources) != 80 {
			t.Fatal("saturated reporting blocked a local rejection")
		}
		b.close()
	})
}

func TestTemporaryBlockCountersStayBoundedAndExpireWithoutWorkers(t *testing.T) {
	b := newTemporaryBlocks(t.Context(), func(context.Context, policy.Rejections) error { return nil }, nil)
	defer b.close()
	now := time.Now()
	for n := range 8192 {
		source := netip.AddrFrom4([4]byte{198, 51, byte(n >> 8), byte(n)})
		b.reject(source, eligibleRejection, now)
	}
	if len(b.sources) != 4096 {
		t.Fatal("source counters are not bounded", len(b.sources))
	}
	source := netip.MustParseAddr("203.0.113.1")
	b.reject(source, eligibleRejection, now.Add(policy.BlockWindow))
	if len(b.sources) != 1 {
		t.Fatal("expired counters were not reclaimed", len(b.sources))
	}
}
