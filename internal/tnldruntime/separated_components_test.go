package tnldruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestSeparatedRuntimeComponent(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierRuntimeLoad)
	component := *separatedComponent
	if component == "" || component == "setup" || component == "coordinator" {
		t.Skip("run task go:test:load:runtime")
	}
	routes, rate, _ := separatedLoadParameters(t)
	ctx, cancel := signal.NotifyContext(t.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	coordination := separatedCoordination(t)
	waitForIntegrationCondition(t, 30*time.Second, func(ctx context.Context) (bool, error) { return coordination.Get(ctx, "coordinator.ready", nil) })
	var orders atomic.Int64
	serveSeparatedResources(t, orders.Load)
	separatedWrite(t, component+".resources-ready", true)
	switch component {
	case "pebble":
		runSeparatedPebble(t, ctx)
	case "app", "app-2", "app-3", "app-4":
		runSeparatedApp(t, ctx, component)
	case "publishers", "publishers-2", "publishers-3", "publishers-4":
		runSeparatedPublishers(t, ctx, routes, slices.Index(separatedPublisherComponents(), component))
	case "visitor-1", "visitor-2", "visitor-3", "visitor-4":
		runSeparatedVisitor(t, ctx, component, rate)
	case "control-a", "control-b", "ingress-a", "ingress-b", "relay-a", "relay-b", "relay-a-2", "relay-b-2":
		if !separatedRead(t, ctx, "pebble.ready", nil) {
			return
		}
		if component != "control-a" && !separatedRead(t, ctx, "control-a.ready", nil) {
			return
		}
		client := separatedHTTP(t)
		base := client.Transport
		client.Transport = splitACMERoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodPost && request.URL.Path == "/order-plz" {
				orders.Add(1)
			}
			return base.RoundTrip(request)
		})
		cfg := separatedConfig(t, component)
		if component != "control-a" {
			separatedWrite(t, component+".admission-limits", separatedAdmissionFrom(cfg))
		}
		options := integrationProcessOptions{acmeHTTPClient: client,
			serviceHTTPClient: splitTestServiceHTTPClient(t, separatedRoots(t, "roots.pem"), "control:9443"),
			relayClientTLS:    separatedRelayTLS(t), owner: newRuntimeTopology(t)}
		process := startIntegrationProcessWithOptions(t, cfg, options)
		defer captureSeparatedFailure(t, component)
		waitForProcessReady(t, process)
		readyName := component + ".ready"
		if component == "relay-a" && *runtimeLoadScenario == "relay-kill" {
			if found, err := coordination.Get(ctx, readyName, nil); err != nil {
				t.Fatal(err)
			} else if found {
				readyName = "relay-a.restarted"
			}
		}
		separatedWrite(t, readyName, time.Now())
		if component == "ingress-a" || component == "ingress-b" {
			if !separatedRead(t, ctx, component+".stop", nil) {
				return
			}
			if *runtimeLoadCapacityOnly {
				stopIntegrationProcessWithin(t, process, 35*time.Second)
			} else {
				stopIntegrationProcess(t, process)
			}
			separatedWrite(t, component+".stopped", time.Now())
			<-ctx.Done()
			return
		}
		if component == "relay-a" && *runtimeLoadScenario == "relay-restart" && !*runtimeLoadCapacityOnly {
			if !separatedRead(t, ctx, "relay-a.restart", nil) {
				return
			}
			stopped := separatedRestart{Started: time.Now()}
			stopIntegrationProcess(t, process)
			stopped.Exited = time.Now()
			separatedWrite(t, "relay-a.stopped", stopped)
			process = startIntegrationProcessWithOptions(t, cfg, options)
			waitForProcessReady(t, process)
			separatedWrite(t, "relay-a.restarted", time.Now())
		}
		if component == "control-a" && *runtimeLoadScenario == "control-restart" {
			if !separatedRead(t, ctx, "control-a.restart", nil) {
				return
			}
			stopped := separatedRestart{Started: time.Now()}
			stopIntegrationProcess(t, process)
			stopped.Exited = time.Now()
			separatedWrite(t, "control-a.stopped", stopped)
			// keep one control unavailable beyond a process lease while the
			// surviving control must continue renewing ingress and relay leases.
			wait := time.NewTimer(35 * time.Second)
			select {
			case <-ctx.Done():
				wait.Stop()
				return
			case <-wait.C:
			}
			process = startIntegrationProcessWithOptions(t, cfg, options)
			waitForProcessReady(t, process)
			separatedWrite(t, "control-a.restarted", time.Now())
		}
		select {
		case <-ctx.Done():
		case <-process.done:
			t.Fatalf("%s exited during workload: %v", component, process.result())
		}
	default:
		t.Fatal("unknown separated component")
	}
}

func runSeparatedPebble(t *testing.T, ctx context.Context) {
	var address net.IP
	waitForIntegrationCondition(t, 10*time.Second, func(context.Context) (bool, error) {
		ips, err := net.LookupIP("ingress")
		if err != nil {
			return false, err
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				address = ip.To4()
				break
			}
		}
		return address != nil, nil
	})
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		message := new(dns.Msg)
		message.SetReply(request)
		message.Authoritative = true
		for _, question := range request.Question {
			if question.Qtype == dns.TypeA {
				message.Answer = append(message.Answer, &dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: address})
			}
		}
		_ = w.WriteMsg(message)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8053")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:8053")
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	startOwnedDNSServer(t, &dns.Server{Listener: listener, Handler: handler})
	startOwnedDNSServer(t, &dns.Server{PacketConn: packet, Handler: handler})
	command := exec.Command("pebble", "-config", "/load/pebble-config.json", "-strict=false", "-dnsserver", "127.0.0.1:8053")
	command.Env = append(os.Environ(), "PEBBLE_AUTHZREUSE=0", "PEBBLE_VA_ALWAYS_VALID=0", "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0")
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	process, err := startOwnedCommand(command, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.shutdown(5*time.Second, 5*time.Second); err != nil {
			t.Error(err)
		}
	})
	client := separatedHTTP(t)
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		_, pem, ready := integrationPebbleRoots(ctx, client, "https://pebble:14000/dir", "https://pebble:15000/roots/0")
		if ready {
			if err := os.WriteFile("/load/route-roots.pem", pem, 0o600); err != nil {
				return false, err
			}
		}
		return ready, nil
	})
	separatedWrite(t, "pebble.ready", time.Now())
	select {
	case <-ctx.Done():
	case <-process.done:
		t.Fatalf("Pebble exited during workload: %v", process.result())
	}
}

func runSeparatedApp(t *testing.T, ctx context.Context, component string) {
	handler := benchworkload.Origin(32768)
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: handler}
	tlsListener, err := net.Listen("tcp", ":8444")
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	tlsServer := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: 30 * time.Second, Handler: handler}
	done, tlsDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	go func() {
		defer close(tlsDone)
		_ = tlsServer.ServeTLS(tlsListener, "/load/direct.pem", "/load/direct.key")
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = tlsServer.Close()
		<-done
		<-tlsDone
	})
	separatedWrite(t, component+".ready", time.Now())
	<-ctx.Done()
}

type separatedPublishers struct {
	URLs               []string
	Ready              []publisher.Event
	Fallbacks          int64
	Activation         []time.Duration
	ActivationDuration time.Duration
}

func separatedPublisherIndexes(count, shard int) []int {
	shards := len(separatedPublisherComponents())
	indexes := make([]int, 0, (count+shards-1)/shards)
	for i := 2 * shard; i < count; i += 2 * shards {
		indexes = append(indexes, i)
		if i+1 < count {
			indexes = append(indexes, i+1)
		}
	}
	return indexes
}

func TestSeparatedPublisherIndexesCoverRoutesAndTransports(t *testing.T) {
	for _, total := range []int{4, 8, 17, 3000} {
		seen := make([]bool, total)
		for shard := range separatedPublisherComponents() {
			indexes := separatedPublisherIndexes(total, shard)
			for _, index := range indexes {
				if index < 0 || index >= total || seen[index] {
					t.Fatalf("total=%d shard=%d duplicate/invalid index=%d", total, shard, index)
				}
				seen[index] = true
			}
			if total >= 8 && (indexes[0]%2 == indexes[1]%2) {
				t.Fatalf("total=%d shard=%d has no mixed transports", total, shard)
			}
			if total >= 64 {
				var firstWindow int
				for _, index := range indexes {
					if index < 64 {
						firstWindow++
					}
				}
				if firstWindow != 64/len(separatedPublisherComponents()) {
					t.Fatalf("total=%d shard=%d owns %d of first 64 routes", total, shard, firstWindow)
				}
			}
		}
		for index, found := range seen {
			if !found {
				t.Fatalf("total=%d missing index=%d", total, index)
			}
		}
	}
}

func runSeparatedPublishers(t *testing.T, ctx context.Context, count, shard int) {
	separatedWrite(t, separatedPublisherShardKey(shard, "request-limit"), runtimeLoadAdmission.PublisherRequestLimit)
	if !separatedRead(t, ctx, "publish.start", nil) {
		return
	}
	var prefixes []string
	for index := 1; index <= 4; index++ {
		ips, err := net.LookupIP("visitor-" + strconv.Itoa(index))
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				prefixes = append(prefixes, ip.String()+"/32")
			}
		}
	}
	transport := "mixed"
	if *runtimeLoadScenario == "udp-fallback" {
		transport = "auto"
	}
	var fallbacks atomic.Int64
	client := separatedHTTP(t)
	inspect := inspectStandaloneTestDatabase(t, testutil.PostgresURL(t))
	if *runtimeLoadTrace {
		traceRuntimeCertificateHTTP(t, client, time.Now())
	}
	group, err := benchworkload.OpenPublishers(ctx, benchworkload.PublisherConfig{
		Server: "https://control." + separatedDomain, LoginToken: testLoginToken,
		Domain: "routes." + separatedDomain, StateRoot: filepath.Join(t.TempDir(), "state"), Target: "http://127.0.0.1:8080",
		HTTPClient: client, RelayTLS: separatedRelayTLS(t), AllowedIPPrefixes: prefixes,
		Transport: transport, Parallel: 4, StartParallel: max(1, *runtimeLoadStartParallel/len(separatedPublisherComponents())),
		RequestLimit: runtimeLoadAdmission.PublisherRequestLimit,
		ReadyTimeout: *runtimeLoadReadyTimeout, StopTimeout: 10 * time.Second, DrainTime: time.Second,
		OnActivationFailure: func(index int) {
			if err := captureSeparatedPublisherFailure(inspect, index); err != nil {
				t.Logf("publisher failure snapshot: %v", err)
			}
		},
		Observe: func(index int, event publisher.Event) error {
			if event.Type == publisher.EventTransportFallback {
				fallbacks.Add(1)
				t.Logf("publisher_transport index=%d event=%s transport=%s", index, event.Type, event.Transport)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(count+1)*10*time.Second)
		defer cancel()
		if _, err := group.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	monitor, stopMonitor := context.WithCancel(ctx)
	defer stopMonitor()
	go func() {
		select {
		case err := <-group.Failures():
			failureCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = separatedCoordination(t).Put(failureCtx, "failure", err.Error())
			stopMonitor()
		case <-monitor.Done():
		}
	}()
	result := separatedPublishers{URLs: make([]string, count), Ready: make([]publisher.Event, count)}
	started := time.Now()
	ready, err := group.Start(monitor, separatedPublisherIndexes(count, shard))
	result.ActivationDuration = time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range ready {
		result.Activation = append(result.Activation, route.Activation)
		result.Ready[route.Index], result.URLs[route.Index] = route.Ready, route.Ready.PublicURL
		t.Logf("separated_activation index=%d launch_to_ready=%s", route.Index, route.Activation)
	}
	t.Logf("separated_activation_total=%s", time.Since(started))
	result.Fallbacks = fallbacks.Load()
	separatedWrite(t, separatedPublisherShardKey(shard, "ready"), result)
	for _, phase := range []string{"close-half", "close-all"} {
		if !separatedRead(t, monitor, phase, nil) {
			return
		}
		at := time.Now()
		indexes := slices.DeleteFunc(separatedPublisherIndexes(count, shard), func(index int) bool {
			return (index < count/2) != (phase == "close-half")
		})
		if _, err := group.Stop(ctx, indexes); err != nil {
			t.Fatal(err)
		}
		separatedWrite(t, separatedPublisherShardKey(shard, phase+".done"), time.Since(at))
	}
	<-ctx.Done()
}

type separatedRestart struct{ Started, Exited, Restored time.Time }
type separatedVisitorResult struct {
	benchworkload.VisitorResult
	Bandwidth           *benchworkload.BandwidthResult
	Requests            []benchworkload.RequestResult
	RequestsFile        string `json:"requests_file,omitempty"`
	HeldRequested       int
	HeldOpened          int
	HeldSurviving       int
	HeldProgressing     int
	HeldClosed          int
	HeldOpeningDuration time.Duration
	HealthyHeld         int
	HealthyHeldProgress int
	Cohorts             map[string]benchworkload.VisitorResult
}

func runSeparatedVisitor(t *testing.T, ctx context.Context, component string, rate int) {
	lifecycle := ctx
	ctx, stopFailures := separatedCoordination(t).WorkloadContext(ctx)
	defer stopFailures()
	var publishers separatedPublishers
	if !separatedRead(t, ctx, "publishers.ready", &publishers) {
		return
	}
	if !separatedRead(t, ctx, "visitors.start", nil) {
		return
	}
	index, _ := strconv.Atoi(strings.TrimPrefix(component, "visitor-"))
	visitor := benchworkload.Visitor{Roots: separatedRoots(t, "route-roots.pem"), Address: "ingress:443", PayloadBytes: 32768}
	directVisitor := benchworkload.Visitor{Roots: separatedRoots(t, "roots.pem"), Address: "publishers:8444", PayloadBytes: 32768}
	localRate := benchworkload.Assignment(rate, 4, index-1)
	cohortByURL := make(map[string]string)
	for i, url := range publishers.URLs {
		cohortByURL[url] = "quic"
		if i%2 != 0 || *runtimeLoadScenario == "udp-fallback" {
			cohortByURL[url] = "tls-tcp"
		}
	}
	var streams []*benchworkload.HeldStream
	var directStreams []*benchworkload.HeldStream
	var healthy []*benchworkload.HeldStream
	separatedWrite(t, component+".ready", time.Now())
	for sequence := 0; ; sequence++ {
		var phase benchworkload.Phase
		if !separatedRead(t, ctx, fmt.Sprintf("phase-%d", sequence), &phase) {
			return
		}
		if phase.Done {
			break
		}
		result := separatedVisitorResult{}
		phaseVisitor := visitor
		if phase.Direct {
			phaseVisitor = directVisitor
		}
		if phase.HeldStreams > 0 {
			result.HeldRequested = benchworkload.Assignment(phase.HeldStreams, 4, index-1)
			openedAt := time.Now()
			opened := openSeparatedHeld(t, ctx, phaseVisitor, phase.URLs, phase.HeldStreams, index-1)
			result.HeldOpeningDuration = time.Since(openedAt)
			result.HeldOpened = len(opened)
			if phase.Direct {
				directStreams = append(directStreams, opened...)
			} else {
				streams = append(streams, opened...)
			}
		}
		if phase.OpenHeld {
			healthy = append(healthy, openSeparatedHeld(t, ctx, visitor, phase.URLs, min(8, len(phase.URLs)), index-1)...)
		}
		measured := streams
		if phase.Direct {
			measured = directStreams
		}
		beforeBytes := make([]int64, len(measured))
		endedEarly := 0
		for i, stream := range measured {
			beforeBytes[i] = stream.BytesReceived()
		}
		progress := make([]int64, len(healthy))
		for i, stream := range healthy {
			progress[i] = stream.BytesReceived()
		}
		if phase.Duration == 0 {
			interval := time.Second / time.Duration(max(1, localRate))
			pacer := time.NewTicker(interval)
			for i := index - 1; i < len(phase.URLs); i += 4 {
				select {
				case <-ctx.Done():
					pacer.Stop()
					return
				case <-pacer.C:
				}
				row := phaseVisitor.Request(ctx, phase.URLs[i], time.Now())
				if row.Error != "" {
					t.Error(row.Error)
				}
				result.Requests = append(result.Requests, row)
			}
			pacer.Stop()
		} else if phase.Bandwidth != nil {
			var freshDone chan error
			if phase.Combined {
				freshDone = make(chan error, 1)
				go func() {
					freshDone <- runSeparatedVisitorFresh(ctx, phaseVisitor, phase, component, rate, localRate, index, cohortByURL, &result)
				}()
			}
			localConfig := *phase.Bandwidth
			localConfig.Start, localConfig.Duration = phase.Start, phase.Duration
			localConfig.Streams, localConfig.BytesPerSecond = 0, 0
			var localURLs []string
			for stream := index - 1; stream < phase.Bandwidth.Streams; stream += 4 {
				localConfig.Streams++
				localConfig.BytesPerSecond += phase.Bandwidth.BytesPerSecond / int64(phase.Bandwidth.Streams)
				if int64(stream) < phase.Bandwidth.BytesPerSecond%int64(phase.Bandwidth.Streams) {
					localConfig.BytesPerSecond++
				}
				localURLs = append(localURLs, phase.URLs[stream%len(phase.URLs)])
			}
			if localConfig.Streams > 0 {
				bandwidth, err := phaseVisitor.Bandwidth(ctx, localConfig, localURLs)
				result.Bandwidth = &bandwidth
				if err != nil {
					t.Error(err)
				}
			}
			if freshDone != nil {
				if err := <-freshDone; err != nil {
					t.Error(err)
				}
			}
		} else {
			if err := runSeparatedVisitorFresh(ctx, phaseVisitor, phase, component, rate, localRate, index, cohortByURL, &result); err != nil {
				t.Fatal(err)
			}
		}
		for i, stream := range healthy {
			if stream.Alive() {
				result.HealthyHeld++
			}
			if stream.Alive() && stream.BytesReceived() > progress[i] {
				result.HealthyHeldProgress++
			}
			if phase.Duration > 0 && (!stream.Alive() || stream.BytesReceived() <= progress[i]) {
				t.Error("healthy-path held stream stopped delivering")
			}
			if phase.CloseHeld {
				if err := stream.Close(); err != nil {
					t.Error(err)
				}
			}
		}
		if phase.CloseHeld {
			healthy = nil
		}
		for i, stream := range measured {
			if stream.Alive() {
				result.HeldSurviving++
			}
			if stream.Alive() && stream.BytesReceived() > beforeBytes[i] {
				result.HeldProgressing++
			}
			if (phase.Name == "steady" || phase.Name == "direct-held-steady" || strings.HasSuffix(phase.Name, "held-warmup") || runtimeEarlyFault(*runtimeLoadScenario) && phase.CloseHeld) && !stream.Alive() {
				endedEarly++
			}
			if phase.CloseHeld {
				if err := stream.Close(); err != nil {
					t.Error(err)
				}
				result.HeldClosed++
			}
		}
		if endedEarly > 0 {
			t.Errorf("%d held streams ended before their permitted close boundary", endedEarly)
		}
		if phase.CloseHeld {
			if phase.Direct {
				directStreams = nil
			} else {
				streams = nil
			}
		}
		separatedWrite(t, phase.Name+"."+component, result)
	}
	separatedWrite(t, component+".done", !t.Failed())
	<-lifecycle.Done()
}

func runSeparatedVisitorFresh(ctx context.Context, visitor benchworkload.Visitor, phase benchworkload.Phase, component string, rate, localRate, index int, cohortByURL map[string]string, result *separatedVisitorResult) error {
	result.Cohorts = make(map[string]benchworkload.VisitorResult)
	var requestFile *os.File
	var requestWriter *bufio.Writer
	var requestEncoder *json.Encoder
	var requestError error
	if *runtimeLoadCapacityOnly && int64(localRate)*int64(phase.Duration)/int64(time.Second) > 25_000 {
		result.RequestsFile = fmt.Sprintf("%s-%s-requests.jsonl", phase.Name, component)
		var err error
		requestFile, err = os.Create(filepath.Join("/results", result.RequestsFile))
		if err != nil {
			return err
		}
		requestWriter = bufio.NewWriter(requestFile)
		requestEncoder = json.NewEncoder(requestWriter)
	}
	cfg := benchworkload.VisitorConfig{Rate: localRate,
		Workers: benchworkload.Assignment(*runtimeLoadWorkers, 4, index-1), QueueSlots: benchworkload.Assignment(*runtimeLoadQueue, 4, index-1),
		Start: phase.Start.Add(time.Duration(index-1) * time.Second / time.Duration(rate)), Duration: phase.Duration,
		OnResult: func(row benchworkload.RequestResult) {
			if requestEncoder != nil {
				if requestError == nil {
					requestError = requestEncoder.Encode(row)
				}
			} else {
				result.Requests = append(result.Requests, row)
			}
			name := cohortByURL[row.URL]
			if phase.Direct {
				name = "direct"
			}
			cohort := result.Cohorts[name]
			cohort.Scheduled++
			cohort.Observe(row)
			result.Cohorts[name] = cohort
		},
	}
	var err error
	result.VisitorResult, err = visitor.Run(ctx, cfg, phase.URLs)
	if requestWriter != nil {
		requestError = errors.Join(requestError, requestWriter.Flush(), requestFile.Close())
	}
	return errors.Join(err, requestError)
}

func openSeparatedHeld(t *testing.T, ctx context.Context, visitor benchworkload.Visitor, urls []string, total, index int) []*benchworkload.HeldStream {
	t.Helper()
	var streams []*benchworkload.HeldStream
	interval := time.Second / 500 // offered held-stream opening workload per visitor.
	pacer := time.NewTicker(interval)
	defer pacer.Stop()
	for i := index; i < total; i += 4 {
		select {
		case <-ctx.Done():
			return streams
		case <-pacer.C:
		}
		stream, err := visitor.Hold(ctx, urls[i%len(urls)])
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, stream)
		t.Cleanup(func() {
			if err := stream.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	return streams
}

// decode resources through a bounded request; no Docker socket is mounted in a
// workload container. the HTTP listener is only on the disposable Compose network.
func separatedResource(t *testing.T, component string) separatedResources {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	address := component + ":9091"
	if slices.Contains(separatedAppComponents(), component) {
		address = separatedAppPublisher(component) + ":9092"
	}
	response, err := integrationGET(integrationOperationContext(t), client, "http://"+address+"/resources")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var value separatedResources
	if response.StatusCode != http.StatusOK {
		t.Fatalf("resource status for %s: %s", component, response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
