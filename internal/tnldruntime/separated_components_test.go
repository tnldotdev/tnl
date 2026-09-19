package tnldruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestSeparatedRuntimeComponent(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierSeparatedLoad)
	component := *separatedComponent
	if component == "" || component == "setup" || component == "coordinator" {
		t.Skip("run task go:test:load:runtime:separated")
	}
	routes, rate, _ := separatedLoadParameters(t)
	ctx, cancel := signal.NotifyContext(t.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
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
		separatedWrite(t, component+".ready", time.Now())
		if component == "ingress" {
			if !separatedRead(t, ctx, "ingress.stop", nil) {
				return
			}
			stopIntegrationProcess(t, process)
			separatedWrite(t, "ingress.stopped", time.Now())
			<-ctx.Done()
			return
		}
		if component == "relay-a" {
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
	payload := bytes.Repeat([]byte("tnl!"), 8192)
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stream" {
			_, _ = w.Write(payload)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "ready\n")
		w.(http.Flusher).Flush()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				if _, err := io.WriteString(w, "tick\n"); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}
	})}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); <-done })
	separatedWrite(t, "app.ready", time.Now())
	<-ctx.Done()
}

type separatedPublishers struct {
	URLs  []string
	Ready []publisher.Event
}

func runSeparatedPublishers(t *testing.T, ctx context.Context, count int) {
	if !separatedRead(t, ctx, "publish.start", nil) {
		return
	}
	owner := newRuntimeTopology(t)
	identity := newIntegrationPublishingIdentity(t, "https://control."+separatedDomain, separatedHTTP(t), "runtime-load", owner)
	quic := muxsession.QUICConnector{TLSConfig: separatedRelayTLS(t)}
	tcp := muxsession.TLSYamuxConnector{TLSConfig: separatedRelayTLS(t)}
	_, namespace, _ := strings.Cut(identity.hostname, ".")
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
	handles := make([]*integrationPublisher, count)
	result := separatedPublishers{URLs: make([]string, count), Ready: make([]publisher.Event, count)}
	started := time.Now()
	for offset := 0; offset < count; offset += 4 {
		batch := time.Now()
		for index := offset; index < min(offset+4, count); index++ {
			cfg := identity.publisherConfig("http://127.0.0.1:8080", quic, tcp)
			cfg.Hostname = "runtime-" + strconv.Itoa(index) + "." + namespace
			cfg.AllowedIPPrefixes = prefixes
			cfg.FallbackDelay = 250 * time.Millisecond
			if index%2 == 0 {
				cfg.TCPConnector, _ = disabledIntegrationConnector("QUIC cohort")
			} else {
				cfg.QUICConnector, _ = disabledIntegrationConnector("TLS/TCP cohort")
			}
			handles[index] = startOwnedIntegrationPublisher(t, owner, cfg, nil)
		}
		for index := offset; index < min(offset+4, count); index++ {
			result.Ready[index] = waitForPublisherReady(t, handles[index])
			result.URLs[index] = result.Ready[index].PublicURL
			t.Logf("separated_activation index=%d elapsed=%s launch_to_ready_observed=%s", index, time.Since(started), time.Since(batch))
		}
	}
	separatedWrite(t, "publishers.ready", result)
	for _, phase := range []string{"close-half", "close-all"} {
		if !separatedRead(t, ctx, phase, nil) {
			return
		}
		at := time.Now()
		if phase == "close-half" {
			stopRuntimeLoadPublishers(t, handles[:count/2])
		} else {
			stopRuntimeLoadPublishers(t, handles[count/2:])
		}
		separatedWrite(t, phase+".done", time.Since(at))
	}
	<-ctx.Done()
}

type separatedRestart struct{ Started, Exited time.Time }
type separatedRequest struct {
	Started, FirstByte time.Time
	Duration           time.Duration
	Error              string
}
type separatedVisitorResult struct {
	Requests      []separatedRequest
	Missed        int
	HeldSurviving int
}

func runSeparatedVisitor(t *testing.T, ctx context.Context, component string, rate int) {
	var publishers separatedPublishers
	if !separatedRead(t, ctx, "publishers.ready", &publishers) {
		return
	}
	if !separatedRead(t, ctx, "visitors.start", nil) {
		return
	}
	index, _ := strconv.Atoi(strings.TrimPrefix(component, "visitor-"))
	visitor := newIntegrationVisitor(t, separatedRoots(t, "route-roots.pem"), "ingress:443")
	payload := bytes.Repeat([]byte("tnl!"), 8192)
	// Four real source IPs, two workers/queue slots each: aggregate 8/8.
	localRate := rate / 4
	if index <= rate%4 {
		localRate++
	}
	var streams []*runtimeLoadStream
	for i := index - 1; i < min(8, len(publishers.URLs)); i += 4 {
		streams = append(streams, startRuntimeLoadStream(t, visitor.transport, publishers.URLs[i]))
	}
	separatedWrite(t, component+".ready", time.Now())
	for _, phase := range []string{"steady", "relay-restart", "shutdown"} {
		var start time.Time
		if !separatedRead(t, ctx, phase+".start", &start) {
			return
		}
		// Spread the four sources' first offers over one global scheduling period.
		waitUntilIntegrationTime(t, start.Add(time.Duration(index-1)*time.Second/time.Duration(rate)))
		urls := publishers.URLs
		if phase == "shutdown" {
			urls = urls[len(urls)/2:]
		}
		load := startRuntimeLoadVisitorWorkers(t, visitor.client, urls, payload, localRate, 2, func(url string) { t.Logf("separated_visitor_first_failure url=%s", url) })
		var stop time.Time
		if !separatedRead(t, ctx, phase+".stop", &stop) {
			load.stop(t, "cleanup")
			return
		}
		waitUntilIntegrationTime(t, stop)
		rows := load.stop(t, phase)
		result := separatedVisitorResult{Missed: load.missed}
		for _, row := range rows {
			value := separatedRequest{Started: row.started, FirstByte: row.firstByte, Duration: row.duration}
			if row.err != nil {
				value.Error = row.err.Error()
			}
			result.Requests = append(result.Requests, value)
		}
		if phase == "relay-restart" {
			for _, stream := range streams {
				select {
				case <-stream.done:
				default:
					result.HeldSurviving++
				}
				stream.stop(t)
			}
		}
		separatedWrite(t, phase+"."+component, result)
	}
	// Every route receives a fresh verified request after repair/shutdown if live.
	for _, url := range publishers.URLs[len(publishers.URLs)/2:] {
		if result := runtimeLoadRequest(ctx, visitor.client, url, payload); result.err != nil {
			t.Error(result.err)
		}
	}
	separatedWrite(t, component+".done", !t.Failed())
	<-ctx.Done()
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
