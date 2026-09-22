package tnldruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
	switch component {
	case "pebble":
		runSeparatedPebble(t, ctx)
	case "app":
		runSeparatedApp(t, ctx)
	case "publishers":
		runSeparatedPublishers(t, ctx, routes)
	case "visitor-1", "visitor-2", "visitor-3", "visitor-4":
		runSeparatedVisitor(t, ctx, component, rate)
	case "control", "ingress", "relay-a", "relay-b":
		if !separatedRead(t, ctx, "pebble.ready", nil) {
			return
		}
		if component != "control" && !separatedRead(t, ctx, "control.ready", nil) {
			return
		}
		client := separatedHTTP(t)
		if component == "control" && *runtimeLoadTrace {
			traceRuntimeCertificateHTTP(t, client, time.Now())
		}
		base := client.Transport
		client.Transport = splitACMERoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodPost && request.URL.Path == "/order-plz" {
				orders.Add(1)
			}
			return base.RoundTrip(request)
		})
		cfg := separatedConfig(t, component)
		options := integrationProcessOptions{acmeHTTPClient: client,
			serviceHTTPClient: splitTestServiceHTTPClient(t, separatedRoots(t, "roots.pem"), "control:9443"),
			relayClientTLS:    separatedRelayTLS(t), owner: newRuntimeTopology(t)}
		process := startIntegrationProcessWithOptions(t, cfg, options)
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
		if component == "ingress" {
			if !separatedRead(t, ctx, "ingress.stop", nil) {
				return
			}
			stopIntegrationProcess(t, process)
			separatedWrite(t, "ingress.stopped", time.Now())
			<-ctx.Done()
			return
		}
		if component == "relay-a" && *runtimeLoadScenario == "relay-restart" {
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

func runSeparatedApp(t *testing.T, ctx context.Context) {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: benchworkload.Origin(32768)}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); <-done })
	separatedWrite(t, "app.ready", time.Now())
	<-ctx.Done()
}

type separatedPublishers struct {
	URLs      []string
	Ready     []publisher.Event
	Fallbacks int64
}

func runSeparatedPublishers(t *testing.T, ctx context.Context, count int) {
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
	group, err := benchworkload.OpenPublishers(ctx, benchworkload.PublisherConfig{
		Server: "https://control." + separatedDomain, LoginToken: testLoginToken,
		Domain: "routes." + separatedDomain, StateRoot: filepath.Join(t.TempDir(), "state"), Target: "http://127.0.0.1:8080",
		HTTPClient: separatedHTTP(t), RelayTLS: separatedRelayTLS(t), AllowedIPPrefixes: prefixes,
		Transport: transport, Parallel: 4, ReadyTimeout: 30 * time.Second, StopTimeout: 10 * time.Second, DrainTime: time.Second,
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
	ready, err := group.Start(monitor, benchworkload.RouteIndexes(count, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range ready {
		result.Ready[route.Index], result.URLs[route.Index] = route.Ready, route.Ready.PublicURL
		t.Logf("separated_activation index=%d launch_to_ready=%s", route.Index, route.Activation)
	}
	t.Logf("separated_activation_total=%s", time.Since(started))
	result.Fallbacks = fallbacks.Load()
	separatedWrite(t, "publishers.ready", result)
	for _, phase := range []string{"close-half", "close-all"} {
		if !separatedRead(t, monitor, phase, nil) {
			return
		}
		at := time.Now()
		indexes := benchworkload.RouteIndexes(count, 1, 0)
		if phase == "close-half" {
			indexes = indexes[:count/2]
		} else {
			indexes = indexes[count/2:]
		}
		if _, err := group.Stop(ctx, indexes); err != nil {
			t.Fatal(err)
		}
		separatedWrite(t, phase+".done", time.Since(at))
	}
	<-ctx.Done()
}

type separatedRestart struct{ Started, Exited, Restored time.Time }
type separatedVisitorResult struct {
	benchworkload.VisitorResult
	Requests            []benchworkload.RequestResult
	HeldSurviving       int
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
	localRate := benchworkload.Assignment(rate, 4, index-1)
	cohortByURL := make(map[string]string)
	for i, url := range publishers.URLs {
		cohortByURL[url] = "quic"
		if i%2 != 0 || *runtimeLoadScenario == "udp-fallback" {
			cohortByURL[url] = "tls-tcp"
		}
	}
	streams := openSeparatedHeld(t, ctx, visitor, publishers.URLs, index-1)
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
		if phase.OpenHeld {
			healthy = append(healthy, openSeparatedHeld(t, ctx, visitor, phase.URLs, index-1)...)
		}
		progress := make([]int64, len(healthy))
		for i, stream := range healthy {
			progress[i] = stream.BytesReceived()
		}
		if phase.Duration == 0 {
			for i := index - 1; i < len(phase.URLs); i += 4 {
				row := visitor.Request(ctx, phase.URLs[i], time.Now())
				if row.Error != "" {
					t.Error(row.Error)
				}
				result.Requests = append(result.Requests, row)
			}
		} else {
			result.Cohorts = make(map[string]benchworkload.VisitorResult)
			cfg := benchworkload.VisitorConfig{Rate: localRate,
				Workers: benchworkload.Assignment(*runtimeLoadWorkers, 4, index-1), QueueSlots: benchworkload.Assignment(*runtimeLoadQueue, 4, index-1),
				Start: phase.Start.Add(time.Duration(index-1) * time.Second / time.Duration(rate)), Duration: phase.Duration,
				OnResult: func(row benchworkload.RequestResult) {
					result.Requests = append(result.Requests, row)
					name := cohortByURL[row.URL]
					cohort := result.Cohorts[name]
					cohort.Scheduled++
					cohort.Observe(row)
					result.Cohorts[name] = cohort
				},
			}
			var err error
			result.VisitorResult, err = visitor.Run(ctx, cfg, phase.URLs)
			if err != nil {
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
		for _, stream := range streams {
			if stream.Alive() {
				result.HeldSurviving++
			}
			if (phase.Name == "steady" || runtimeEarlyFault(*runtimeLoadScenario) && phase.CloseHeld) && !stream.Alive() {
				t.Error("held stream ended before its permitted close boundary")
			}
			if phase.CloseHeld {
				if err := stream.Close(); err != nil {
					t.Error(err)
				}
			}
		}
		separatedWrite(t, phase.Name+"."+component, result)
	}
	separatedWrite(t, component+".done", !t.Failed())
	<-lifecycle.Done()
}

func openSeparatedHeld(t *testing.T, ctx context.Context, visitor benchworkload.Visitor, urls []string, index int) []*benchworkload.HeldStream {
	t.Helper()
	var streams []*benchworkload.HeldStream
	for _, i := range benchworkload.RouteIndexes(min(8, len(urls)), 4, index) {
		stream, err := visitor.Hold(ctx, urls[i])
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

// Decode resources through a bounded request; no Docker socket is mounted in a
// workload container. The HTTP listener is only on the disposable Compose network.
func separatedResource(t *testing.T, component string) separatedResources {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	address := component + ":9091"
	if component == "app" {
		address = "publishers:9092"
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
