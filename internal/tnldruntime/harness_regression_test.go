package tnldruntime

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

// this child only runs when selected explicitly by the harness unit tests. it
// needs neither the integration gate nor a built product binary or database.
func TestRuntimeHarnessChild(t *testing.T) {
	mode := os.Getenv("TNL_RUNTIME_HARNESS_CHILD")
	if mode == "" {
		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	defer signal.Stop(signals)
	if mode == "malformed" {
		_, _ = fmt.Fprintln(os.Stdout, "{not json}")
	}
	if mode == "oversized" {
		_, _ = fmt.Fprintln(os.Stdout, strings.Repeat("x", (1<<20)+1))
	}
	for index := range 4096 {
		if _, err := fmt.Fprintf(os.Stdout, "{\"type\":\"progress\",\"publish_run_number\":%d}\n", index); err != nil {
			os.Exit(2)
		}
	}
	_, _ = fmt.Fprintln(os.Stdout, `{"type":"ready"}`)
	switch mode {
	case "interrupt":
		select {
		case <-signals:
		case <-time.After(20 * time.Second):
			os.Exit(3)
		}
		_, _ = fmt.Fprintln(os.Stdout, `{"type":"stopped","reason":"canceled"}`)
	case "ignore_interrupt":
		// Notify consumes interrupts without terminating, forcing escalation.
		<-time.After(20 * time.Second)
		os.Exit(3)
	case "exit_error":
		os.Exit(7)
	}
	os.Exit(0)
}

func harnessChild(t *testing.T, mode string) (*commandOwner, *eventRecorder[integrationBinaryPublishEvent]) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestRuntimeHarnessChild$")
	command.Env = append(os.Environ(), "TNL_RUNTIME_HARNESS_CHILD="+mode)
	events := new(eventRecorder[integrationBinaryPublishEvent])
	writer := &binaryEventWriter{events: events}
	command.Stdout = writer
	var stderr synchronizedBuffer
	command.Stderr = &stderr
	owner, err := startOwnedCommand(command, writer.finish)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		select {
		case <-owner.done:
		default:
			if err := owner.shutdown(100*time.Millisecond, 3*time.Second); err != nil {
				t.Errorf("child cleanup: %v\n%s", err, stderr.String())
			}
		}
	})
	return owner, events
}

func TestBinaryRecorderDrainsWithoutConsumer(t *testing.T) {
	for _, mode := range []string{"burst", "malformed", "oversized", "exit_error"} {
		t.Run(mode, func(t *testing.T) {
			owner, recorder := harnessChild(t, mode)
			if err := waitForDoneWithin(owner.done, 5*time.Second); err != nil {
				t.Fatal("unread output stalled process reap:", err)
			}
			events, parseErr := recorder.snapshot()
			if len(events) != 4097 || events[0].PublishRunNumber != 0 || events[4095].PublishRunNumber != 4095 || events[4096].Type != "ready" {
				t.Fatalf("lost/reordered output: %d events", len(events))
			}
			if mode == "malformed" || mode == "oversized" {
				if parseErr == nil {
					t.Fatal("output error was hidden")
				}
				cursor := 0
				if _, err := recorder.next(t.Context(), &cursor); err == nil {
					t.Fatal("waiter did not see malformed output")
				}
			} else if parseErr != nil {
				t.Fatal(parseErr)
			}
			if mode == "exit_error" {
				var exit *exec.ExitError
				if !errors.As(owner.result(), &exit) || exit.ExitCode() != 7 {
					t.Fatalf("lost child exit error: %v", owner.result())
				}
			} else if err := owner.result(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBinaryRecorderConsumerCancellationAndShutdown(t *testing.T) {
	owner, recorder := harnessChild(t, "interrupt")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cursor := 0
	if _, err := recorder.next(ctx, &cursor); err != nil {
		t.Fatal(err)
	}
	canceled, stopWaiting := context.WithCancel(ctx)
	stopWaiting()
	if _, err := recorder.next(canceled, &cursor); !errors.Is(err, context.Canceled) || cursor != 1 {
		t.Fatalf("canceled cursor = %d, %v", cursor, err)
	}
	// abandon the consumer after one event while the child emits thousands more.
	if err := owner.shutdown(5*time.Second, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := owner.result(); err != nil {
		t.Fatal(err)
	}
	events, err := recorder.snapshot()
	if err != nil || len(events) != 4098 || events[len(events)-1].Type != "stopped" {
		t.Fatalf("shutdown lost output: %d events, %v", len(events), err)
	}
	// a new reader can replay the complete history; the old reader did not steal it.
	replay := 0
	for index := range events {
		event, err := recorder.next(ctx, &replay)
		if err != nil || event != events[index] {
			t.Fatalf("replay %d = %#v, %v", index, event, err)
		}
	}
	if _, err := recorder.next(ctx, &replay); !errors.Is(err, io.EOF) {
		t.Fatalf("end of output = %v", err)
	}
}

func TestCommandOwnerEscalatesAndReaps(t *testing.T) {
	owner, recorder := harnessChild(t, "ignore_interrupt")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cursor := 0
	for {
		event, err := recorder.next(ctx, &cursor)
		if err != nil {
			t.Fatal(err)
		}
		if event.Type == "ready" {
			break
		}
	}
	if err := owner.shutdown(20*time.Millisecond, 3*time.Second); err == nil || !strings.Contains(err.Error(), "killed") {
		t.Fatalf("forced shutdown = %v", err)
	}
	if err := waitForDoneWithin(owner.done, time.Second); err != nil {
		t.Fatal("kill did not reap/join:", err)
	}
	if owner.result() == nil {
		t.Fatal("forced exit error was hidden")
	}
	// repeated cleanup returns promptly and does not signal a reaped process.
	if err := owner.shutdown(time.Hour, time.Hour); err == nil {
		t.Fatal("shutdown failure was not retained")
	}
}

func TestPublisherObserverNeverWaitsForReaders(t *testing.T) {
	handle := new(integrationPublisher)
	const producers, perProducer = 4, 512
	done := make(chan struct{})
	go func() {
		var group sync.WaitGroup
		for range producers {
			group.Go(func() {
				for range perProducer {
					_ = handle.observe(publisher.Event{Type: publisher.EventReady})
				}
			})
		}
		group.Wait()
		close(done)
	}()
	if err := waitForDoneWithin(done, 3*time.Second); err != nil {
		t.Fatal("observer stalled without a reader:", err)
	}
	if got := len(handle.observedEvents()); got != producers*perProducer {
		t.Fatalf("recorded %d observations", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cursor := 0
	if _, err := handle.events.next(ctx, &cursor); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := handle.events.next(ctx, &cursor); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := handle.observe(publisher.Event{Type: publisher.EventDraining}); err != nil {
		t.Fatalf("abandoned observer affected publisher: %v", err)
	}
	if got := len(handle.observedEvents()); got != producers*perProducer+1 {
		t.Fatalf("recorded %d observations after cancellation", got)
	}
}

func TestEventRecorderCanceledWaitLeavesHistoryAvailable(t *testing.T) {
	var recorder eventRecorder[int]
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	cursor := 0
	if _, err := recorder.next(ctx, &cursor); !errors.Is(err, context.DeadlineExceeded) || cursor != 0 {
		t.Fatalf("empty canceled wait = cursor %d, %v", cursor, err)
	}
	recorder.append(42)
	recorder.close()
	if event, err := recorder.next(t.Context(), &cursor); err != nil || event != 42 {
		t.Fatalf("late observation after reader cancellation = %d, %v", event, err)
	}
}

func TestPollConditionBoundsBlockingProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	var calls int
	err := pollCondition(ctx, time.Millisecond, 20*time.Millisecond, func(operation context.Context) (bool, error) {
		calls++
		if _, ok := operation.Deadline(); !ok {
			t.Fatal("probe has no deadline")
		}
		<-operation.Done()
		return false, fmt.Errorf("blocked query: %w", operation.Err())
	})
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "blocked query") || calls < 2 {
		t.Fatalf("poll = %d calls, %v", calls, err)
	}
}

func TestTopologyCleanupKeepsControlUntilAllIncarnationsDrain(t *testing.T) {
	var order eventRecorder[string]
	t.Run("fixture", func(t *testing.T) {
		owner := newRuntimeTopology(t)
		add := func(role tnldconfig.Role, name string) *integrationProcess {
			ctx, cancel := context.WithCancel(context.Background())
			p := &integrationProcess{name: name, cancel: cancel, done: make(chan struct{})}
			owner.own(role, p)
			go func() { <-ctx.Done(); order.append(name); close(p.done) }()
			return p
		}
		oldControl := add(tnldconfig.RoleControl, "old control")
		oldRelay := add(tnldconfig.RoleRelay, "old relay")
		add(tnldconfig.RoleIngress, "ingress")
		stopIntegrationProcess(t, oldRelay)
		stopIntegrationProcess(t, oldControl)
		add(tnldconfig.RoleRelay, "replacement relay")
		add(tnldconfig.RoleControl, "replacement control")
		ctx, cancel := context.WithCancel(context.Background())
		p := &integrationPublisher{cancel: cancel, done: make(chan struct{})}
		owner.publishers = append(owner.publishers, p)
		go func() { <-ctx.Done(); order.append("publisher"); close(p.done) }()
		owner.afterStop = append(owner.afterStop, func() { order.append("resources") })
	})
	events, _ := order.snapshot()
	want := []string{"old relay", "old control", "publisher", "ingress", "replacement relay", "replacement control", "resources"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("cleanup order = %v, want %v", events, want)
	}
}

func TestSeparatedResourceFilesCaptureMemoryAttribution(t *testing.T) {
	files := map[string]string{
		"/sys/fs/cgroup/cpu.max":        "100000 100000",
		"/sys/fs/cgroup/memory.max":     "536870912",
		"/sys/fs/cgroup/cpu.stat":       "usage_usec 11\nnr_periods 12\nnr_throttled 13\nthrottled_usec 14\n",
		"/sys/fs/cgroup/memory.current": "15",
		"/sys/fs/cgroup/memory.peak":    "16",
		"/sys/fs/cgroup/memory.events":  "low 17\nhigh 18\nmax 19\noom 20\noom_kill 21\noom_group_kill 22\n",
		"/sys/fs/cgroup/memory.stat":    "anon 23\nfile 24\nkernel 25\nkernel_stack 26\npagetables 27\nsock 28\nslab 29\nshmem 30\nfile_dirty 31\nfile_writeback 32\n",
		"/proc/net/dev":                 "Inter-| Receive | Transmit\nlo: 1 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0\neth0: 33 0 0 0 0 0 0 0 34 0 0 0 0 0 0 0\n",
	}
	resources, err := readSeparatedResourceFiles(func(path string) (string, error) {
		value, ok := files[path]
		if !ok {
			return "", fmt.Errorf("unexpected resource file %q", path)
		}
		return value, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if resources.CPUQuota != "100000 100000" || resources.MemoryLimit != "536870912" ||
		resources.CPUUsec != 11 || resources.Periods != 12 || resources.ThrottledPeriods != 13 || resources.ThrottledUsec != 14 ||
		resources.Memory != 15 || resources.Peak != 16 || resources.MemoryLowEvents != 17 || resources.MemoryHighEvents != 18 ||
		resources.MemoryMaxEvents != 19 || resources.OOMEvents != 20 || resources.OOMKills != 21 || resources.OOMGroupKills != 22 ||
		resources.MemoryAnon != 23 || resources.MemoryFile != 24 || resources.MemoryKernel != 25 || resources.MemoryKernelStack != 26 ||
		resources.MemoryPageTables != 27 || resources.MemorySock != 28 || resources.MemorySlab != 29 || resources.MemoryShmem != 30 ||
		resources.MemoryFileDirty != 31 || resources.MemoryFileWriteback != 32 || resources.ReceiveBytes != 33 || resources.SendBytes != 34 {
		t.Fatalf("resource evidence = %+v", resources)
	}
}

func TestRelayKillFreshVisitorContract(t *testing.T) {
	exited := time.Unix(100, 0)
	for _, test := range []struct {
		name    string
		row     benchworkload.RequestResult
		wantErr bool
	}{
		{name: "success after exit", row: benchworkload.RequestResult{Started: exited.Add(time.Millisecond)}},
		{name: "started before exit", row: benchworkload.RequestResult{Started: exited.Add(-time.Millisecond)}, wantErr: true},
		{name: "partial response after exit", row: benchworkload.RequestResult{Started: exited.Add(time.Millisecond), Error: "unexpected EOF"}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateRelayKillVisitor(test.row, exited)
			if (err != nil) != test.wantErr {
				t.Fatalf("validation error = %v, want error %t", err, test.wantErr)
			}
		})
	}
}

func TestDNSGateAllowsTrafficAndCancelsAtomically(t *testing.T) {
	f := &integrationRoute53{zoneID: "unit", zone: &integrationDNSZone{Name: "example.test.", records: map[string]integrationDNSRecord{
		"existing.example.test./A": {Name: "existing.example.test.", Type: "A", TTL: 1, Values: []integrationDNSValue{{Value: "127.0.0.1"}}},
	}}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	startOwnedDNSServer(t, &dns.Server{Listener: listener, Handler: dns.HandlerFunc(f.serveDNS)})
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serveRoute53(t, w, r) }))
	cleanupIntegrationHTTPServer(t, f.server, nil)
	entered := make(chan struct{})
	f.setBeforeChange(func(ctx context.Context, change integrationDNSChange) error {
		if change.Record.Name != "blocked.example.test." {
			return nil
		}
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- f.applyChanges(ctx, []integrationDNSChange{{Action: "CREATE", Record: integrationDNSRecord{Name: "blocked.example.test", Type: "A"}}})
	}()
	if err := waitForDone(ctx, entered); err != nil {
		t.Fatal(err)
	}
	query := new(dns.Msg)
	query.SetQuestion("existing.example.test.", dns.TypeA)
	response, _, err := (&dns.Client{Net: "tcp"}).ExchangeContext(ctx, query, listener.Addr().String())
	if err != nil || len(response.Answer) != 1 {
		t.Fatalf("DNS blocked behind gate: %v, %v", response, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, f.server.URL+"/2013-04-01/hostedzone/unit/rrset?name=existing.example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Credential=tnl-integration-only/unit")
	page, err := f.server.Client().Do(request)
	if err != nil {
		t.Fatal("provider GET blocked behind gate:", err)
	}
	_ = page.Body.Close()
	if page.StatusCode != http.StatusOK {
		t.Fatal(page.Status)
	}
	if err := f.applyChanges(ctx, []integrationDNSChange{{Action: "CREATE", Record: integrationDNSRecord{Name: "other.example.test", Type: "A"}}}); err != nil {
		t.Fatal("unrelated change blocked:", err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("gate ignored cancellation")
	}
	f.setBeforeChange(nil)
	if err := f.applyChanges(t.Context(), []integrationDNSChange{
		{Action: "CREATE", Record: integrationDNSRecord{Name: "partial.example.test", Type: "A"}},
		{Action: "DELETE", Record: integrationDNSRecord{Name: "missing.example.test", Type: "A"}},
	}); err == nil {
		t.Fatal("invalid batch accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.zone.records) != 2 || len(f.changes) != 1 {
		t.Fatalf("canceled/invalid batch mutated records: %#v, %#v", f.zone.records, f.changes)
	}
}

func TestRoute53FixtureEncodesMultipleResourceRecords(t *testing.T) {
	response := struct {
		Records []integrationDNSRecord `xml:"ResourceRecordSets>ResourceRecordSet"`
	}{Records: []integrationDNSRecord{{
		Name: "_acme-challenge.example.test.", Type: "TXT", TTL: 60,
		Values: []integrationDNSValue{{Value: "first"}, {Value: "second"}},
	}}}
	var encoded strings.Builder
	if err := xml.NewEncoder(&encoded).EncodeElement(response, xml.StartElement{Name: xml.Name{Local: "ListResourceRecordSetsResponse"}}); err != nil {
		t.Fatal(err)
	}
	const records = "<ResourceRecords><ResourceRecord><Value>first</Value></ResourceRecord><ResourceRecord><Value>second</Value></ResourceRecord></ResourceRecords>"
	if !strings.Contains(encoded.String(), records) {
		t.Fatalf("Route 53 resource records encoded as %s", encoded.String())
	}
	var decoded struct {
		Records []integrationDNSRecord `xml:"ResourceRecordSets>ResourceRecordSet"`
	}
	if err := xml.Unmarshal([]byte(encoded.String()), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Records) != 1 || len(decoded.Records[0].Values) != 2 ||
		decoded.Records[0].Values[0].Value != "first" || decoded.Records[0].Values[1].Value != "second" {
		t.Fatalf("Route 53 resource records decoded as %#v", decoded.Records)
	}
}
