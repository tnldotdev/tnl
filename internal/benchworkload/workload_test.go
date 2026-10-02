package benchworkload

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher"
)

func TestPacedOffersDoNotBackpressureOrExtendWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		result, err := runVisitors(t.Context(), VisitorConfig{Rate: 20, Workers: 1, QueueSlots: 1, Start: start, Duration: time.Second}, []string{"route"}, func(_ context.Context, _ string, at time.Time) RequestResult {
			began := time.Now()
			time.Sleep(300 * time.Millisecond)
			return RequestResult{Scheduled: at, Started: began, FirstByte: time.Now(), Duration: time.Since(at)}
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Scheduled != 20 || result.Missed == 0 || result.Scheduled != result.Missed+result.Started+result.QueueExpired {
			t.Fatalf("lost offers: %+v", result)
		}
		if result.OfferDuration != time.Second || result.DrainDuration <= 0 || result.Err() == nil {
			t.Fatalf("incorrect window/drain outcome: %+v", result)
		}
	})
}

func TestExpiredQueueDoesNotReachNetwork(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	result := (Visitor{PayloadBytes: 32}).Request(t.Context(), server.URL, time.Now().Add(-RequestTimeout))
	if !result.QueueExpired || result.Error == "" || calls.Load() != 0 {
		t.Fatalf("expired request reached network: %+v calls=%d", result, calls.Load())
	}
}

func TestCanceledWindowSeparatesOfferingFromDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()
		result, err := runVisitors(ctx, VisitorConfig{Rate: 20, Workers: 1, Start: time.Now(), Duration: 2 * time.Second}, []string{"route"}, func(ctx context.Context, _ string, at time.Time) RequestResult {
			<-ctx.Done()
			time.Sleep(time.Second)
			return RequestResult{Scheduled: at, Started: at, Error: ctx.Err().Error()}
		})
		if !errors.Is(err, context.DeadlineExceeded) || result.OfferDuration != 500*time.Millisecond || result.DrainDuration != time.Second {
			t.Fatalf("offering=%s drain=%s err=%v", result.OfferDuration, result.DrainDuration, err)
		}
	})
}

func TestVisitorVerifiesTLSHostAndPayloadAndHeldLifetime(t *testing.T) {
	server := httptest.NewTLSServer(Origin(32768))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	visitor := Visitor{Roots: roots, PayloadBytes: 32768}
	row := visitor.Request(t.Context(), server.URL, time.Now())
	if row.Error != "" || row.Bytes != 32768 || row.FirstByte.IsZero() {
		t.Fatalf("valid response failed: %+v", row)
	}
	wrongPayload := visitor
	wrongPayload.PayloadBytes--
	if result := wrongPayload.Request(t.Context(), server.URL, time.Now()); result.Error == "" {
		t.Fatal("accepted wrong payload")
	}
	stream, err := visitor.Hold(t.Context(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if !stream.Alive() {
		t.Fatal("held stream ended at opening")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if stream.Alive() {
		t.Fatal("held stream survived close")
	}
	visitor.Roots = nil
	if result := visitor.Request(t.Context(), server.URL, time.Now()); result.Error == "" {
		t.Fatal("accepted untrusted TLS")
	}
}

func TestVisitorBindsConfiguredIPv4Source(t *testing.T) {
	available, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sourcePort := available.Addr().(*net.TCPAddr).Port
	if err := available.Close(); err != nil {
		t.Fatal(err)
	}
	remote := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote <- r.RemoteAddr
		Origin(32).ServeHTTP(w, r)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	visitor := Visitor{
		Roots: roots, Network: "tcp4", SourceAddress: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sourcePort}, PayloadBytes: 32,
	}
	row := visitor.Request(t.Context(), server.URL, time.Now())
	if row.Error != "" || row.Bytes != 32 {
		t.Fatalf("bound visitor response failed: %+v", row)
	}
	host, port, err := net.SplitHostPort(<-remote)
	if err != nil || host != "127.0.0.1" || port != strconv.Itoa(sourcePort) {
		t.Fatalf("visitor source = %s:%s, %v; want 127.0.0.1:%d", host, port, err, sourcePort)
	}
}

func TestBandwidthPacesAndVerifiesBothDirections(t *testing.T) {
	server := httptest.NewTLSServer(Origin(1))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	config := BandwidthConfig{
		Direction:      BandwidthBidirectional,
		Streams:        2,
		BytesPerSecond: 64_000,
		Start:          time.Now().Add(10 * time.Millisecond),
		Duration:       40 * time.Millisecond,
	}
	result, err := (Visitor{Roots: roots}).Bandwidth(t.Context(), config, []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if result.UploadBytes != 2560 || result.DownloadBytes != 2560 || result.Failures != 0 {
		t.Fatalf("unexpected bandwidth result: %+v", result)
	}
	if result.UploadBytesPerSecond <= 0 || result.DownloadBytesPerSecond <= 0 {
		t.Fatalf("missing achieved rates: %+v", result)
	}
	if result.Elapsed < config.Duration {
		t.Fatalf("bandwidth completed without pacing: %s", result.Elapsed)
	}
	if len(result.Streams) != 4 || len(result.PerSecond) == 0 || result.PerSecond[0].UploadBytes != 2560 || result.PerSecond[0].DownloadBytes != 2560 {
		t.Fatalf("missing verified per-stream and per-second bytes: %+v", result)
	}
	for _, stream := range result.Streams {
		if stream.URL != server.URL || stream.Error != "" || stream.Bytes != stream.ExpectedBytes || stream.Bytes == 0 || stream.LastByteDelay < stream.FirstByteDelay {
			t.Fatalf("invalid verified stream: %+v", stream)
		}
	}
}

func TestBandwidthBucketsVerifiedBytesAcrossSeconds(t *testing.T) {
	server := httptest.NewTLSServer(Origin(1))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	session, err := (Visitor{Roots: roots}).PrepareBandwidth(t.Context(), BandwidthDownstream, 1, 64_000, []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.Run(t.Context(), time.Now().Add(10*time.Millisecond), 1200*time.Millisecond)
	if err != nil || result.DownloadBytes != 76_800 || len(result.PerSecond) < 2 {
		t.Fatalf("paced transfer: %+v, %v", result, err)
	}
	var total int64
	for _, second := range result.PerSecond {
		total += second.DownloadBytes
	}
	if total != result.DownloadBytes || result.PerSecond[0].DownloadBytes == 0 || result.PerSecond[1].DownloadBytes == 0 {
		t.Fatalf("verified bytes lost across seconds: %+v", result.PerSecond)
	}
}

func TestBandwidthPreparesOneConnectionBeforePacingSeveralSegments(t *testing.T) {
	server := httptest.NewUnstartedServer(Origin(1))
	listener := &delayedBandwidthListener{Listener: server.Listener, delay: 400 * time.Millisecond}
	server.Listener = listener
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	session, err := (Visitor{Roots: roots}).PrepareBandwidth(t.Context(), BandwidthDownstream, 1, 64_000, []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if session.setupDuration < listener.delay {
		t.Fatalf("connection setup was not measured: %s", session.setupDuration)
	}
	start := time.Now().Add(10 * time.Millisecond)
	result, err := session.runWithSegmentDuration(t.Context(), start, 200*time.Millisecond, 50*time.Millisecond)
	if err != nil || result.DownloadBytes != 12_800 || result.ExpectedDownloadBytes != 12_800 || result.SetupDuration < listener.delay {
		t.Fatalf("prepared bandwidth = %+v, %v", result, err)
	}
	if count := listener.accepted.Load(); count != 1 {
		t.Fatalf("accepted %d TLS connections for four transfer segments; want one", count)
	}
}

func TestBandwidthSetupRejectsWrongLocalServiceHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-TNL-Bench-Host", "wrong.example")
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	session, err := (Visitor{Roots: roots}).PrepareBandwidth(t.Context(), BandwidthDownstream, 1, 64_000, []string{server.URL})
	if session != nil || err == nil || !strings.Contains(err.Error(), "local service observed the wrong hostname") {
		t.Fatalf("unverified connection accepted: session=%v, err=%v", session, err)
	}
}

func TestBandwidthSegmentGapsAreNotATransferLimit(t *testing.T) {
	origin := Origin(1)
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == bandwidthPath {
			requests.Add(1)
			time.Sleep(300 * time.Millisecond)
		}
		origin.ServeHTTP(w, r)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	session, err := (Visitor{Roots: roots}).PrepareBandwidth(t.Context(), BandwidthDownstream, 1, 64_000, []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	segmented, err := session.runWithSegmentDuration(t.Context(), time.Now().Add(10*time.Millisecond), 150*time.Millisecond, 30*time.Millisecond)
	if err == nil || segmented.Failures != 0 || segmented.DownloadBytes != 9_600 || requests.Load() != 5 {
		t.Fatalf("five complete but late transfers = %+v; requests=%d, err=%v", segmented, requests.Load(), err)
	}
	continuous, err := session.Run(t.Context(), time.Now().Add(10*time.Millisecond), 150*time.Millisecond)
	if err != nil || continuous.DownloadBytes != 9_600 || continuous.Failures != 0 || requests.Load() != 6 {
		t.Fatalf("one continuous transfer = %+v; requests=%d, err=%v", continuous, requests.Load(), err)
	}
}

type delayedBandwidthListener struct {
	net.Listener
	delay    time.Duration
	accepted atomic.Int64
}

func (l *delayedBandwidthListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
		time.Sleep(l.delay)
	}
	return connection, err
}

func TestBandwidthRejectsInvalidConfigurationAndPayload(t *testing.T) {
	config := BandwidthConfig{Direction: "sideways", Streams: 1, BytesPerSecond: 1, Start: time.Now(), Duration: time.Second}
	if _, err := (Visitor{}).Bandwidth(t.Context(), config, []string{"https://example.test"}); err == nil {
		t.Fatal("accepted invalid bandwidth direction")
	}
	verifier := payloadVerifier{}
	if _, err := verifier.Write([]byte{0, 1, 3}); err == nil || verifier.Bytes() != 0 {
		t.Fatalf("accepted invalid deterministic payload: bytes=%d error=%v", verifier.Bytes(), err)
	}
}

func TestBandwidthRejectsLateExactTransfer(t *testing.T) {
	result := BandwidthResult{TargetDuration: time.Second, Elapsed: 2*time.Second + time.Nanosecond}
	if err := result.Err(); !errors.Is(err, ErrBandwidthLate) {
		t.Fatalf("late complete transfer = %v", err)
	}
	result.Elapsed = 2 * time.Second
	if err := result.Err(); err != nil {
		t.Fatalf("rejected a transfer at its completion budget: %v", err)
	}
}

func TestFirstBodyByteExcludesHeaderOnlyResponse(t *testing.T) {
	headers := make(chan struct{})
	body := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-TNL-Bench-Host", r.Host)
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		close(headers)
		<-body
		_, _ = w.Write(Payload(1))
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	done := make(chan RequestResult, 1)
	go func() { done <- (Visitor{Roots: roots, PayloadBytes: 1}).Request(t.Context(), server.URL, time.Now()) }()
	<-headers
	released := time.Now()
	close(body)
	result := <-done
	if result.Error != "" || result.FirstByte.Before(released) {
		t.Fatalf("recorded headers as body: %+v", result)
	}
}

func TestPublisherStartupBoundsAndUnexpectedExit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var active, peak atomic.Int64
		fail := make(chan struct{})
		g := &Publishers{config: PublisherConfig{Parallel: 1, StartParallel: 2, ReadyTimeout: 30 * time.Second, StopTimeout: 10 * time.Second}, ctx: ctx, cancel: cancel, failures: make(chan error, 1), namespace: "example.test"}
		g.run = func(ctx context.Context, config publisher.Config) error {
			current := active.Add(1)
			for old := peak.Load(); current > old; old = peak.Load() {
				if peak.CompareAndSwap(old, current) {
					break
				}
			}
			time.Sleep(time.Second)
			active.Add(-1)
			_ = config.Observe(publisher.Event{Type: publisher.EventReady, PublicURL: "https://" + config.Hostname})
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-fail:
				return errors.New("transport crashed")
			}
		}
		ready, err := g.Start(t.Context(), []int{0, 1, 2, 3})
		if err != nil || len(ready) != 4 || peak.Load() != 2 {
			t.Fatalf("startup: ready=%d peak=%d err=%v", len(ready), peak.Load(), err)
		}
		if _, err := g.Stop(t.Context(), []int{0, 1}); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-g.Failures():
			t.Fatalf("intentional stop failed: %v", err)
		default:
		}
		close(fail)
		synctest.Wait()
		select {
		case <-g.Failures():
		default:
			t.Fatal("unexpected exit was not propagated")
		}
		if _, err := g.Stop(t.Context(), []int{2, 3}); err == nil {
			t.Fatal("lost exit failure during cleanup")
		}
	})
}

func TestCancellationDoesNotHideJoinedCloseFailure(t *testing.T) {
	for _, err := range []error{errors.New("close failed"), context.DeadlineExceeded, errors.Join(context.Canceled, errors.New("close failed"))} {
		if CancellationOnly(err) {
			t.Fatalf("hidden failure: %v", err)
		}
	}
	if !CancellationOnly(errors.Join(context.Canceled, context.Canceled)) {
		t.Fatal("pure cancellation failed")
	}
}

func TestAssignmentsPartitionRoutesAndBalanceBudgets(t *testing.T) {
	seen := make(map[int]bool)
	for worker := range 6 {
		for _, index := range PublicURLIndexes(43, 6, worker) {
			if seen[index] {
				t.Fatal("duplicate route")
			}
			seen[index] = true
		}
	}
	if len(seen) != 43 {
		t.Fatalf("assigned routes = %d, want 43", len(seen))
	}

	for _, test := range []struct{ total, workers int }{{1, 4}, {80, 3}, {1000, 4}} {
		sum, minimum, maximum := 0, test.total, 0
		for index := range test.workers {
			value := Assignment(test.total, test.workers, index)
			sum += value
			minimum, maximum = min(minimum, value), max(maximum, value)
		}
		if sum != test.total || maximum-minimum > 1 {
			t.Fatalf("assignment %d/%d = total %d, range %d..%d", test.total, test.workers, sum, minimum, maximum)
		}
	}
}

func TestCoordinatorImmutableEventsAndFailureUnblock(t *testing.T) {
	server := httptest.NewServer(NewCoordinator().Handler("token"))
	defer server.Close()
	client, err := NewCoordination(server.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Put(t.Context(), "ready", 1); err != nil {
		t.Fatal(err)
	}
	if err := client.Put(t.Context(), "ready", 2); err == nil {
		t.Fatal("event overwrite accepted")
	}
	wrong, _ := NewCoordination(server.URL, "wrong")
	if _, err := wrong.Get(t.Context(), "ready", nil); err == nil {
		t.Fatal("unauthenticated read accepted")
	}
	done := make(chan error, 1)
	go func() { done <- client.Wait(t.Context(), "phase", nil) }()
	if err := client.Put(t.Context(), "failure", "publisher exited"); err != nil {
		t.Fatal(err)
	}
	work, stop := client.WorkloadContext(t.Context())
	defer stop()
	select {
	case <-work.Done():
		if context.Cause(work).Error() != "publisher exited" {
			t.Fatal(context.Cause(work))
		}
	case <-time.After(time.Second):
		t.Fatal("failure did not stop in-flight work")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("failure did not unblock waiter")
		}
	case <-time.After(time.Second):
		t.Fatal("waiter stuck")
	}
	// results remain collectable after failure, and cleanup can still be recorded.
	if err := client.Put(t.Context(), "cleanup", true); err != nil {
		t.Fatal(err)
	}
	if err := client.Wait(t.Context(), "cleanup", nil); err != nil {
		t.Fatal(err)
	}
}
