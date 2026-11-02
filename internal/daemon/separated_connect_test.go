package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/benchworkload"
	clientauth "github.com/tnldotdev/tnl/internal/client/auth"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type connectLoadService struct {
	Service           controlv1.Service
	Target, Transport string
}

type connectLoadPhase struct {
	Name                string
	Start               time.Time
	Duration            time.Duration
	Direct, Reuse, Done bool
}

type connectLoadResult struct {
	Summary  benchworkload.VisitorResult
	Setup    benchworkload.Histogram
	Requests []benchworkload.RequestResult
	Cohorts  map[string]benchworkload.VisitorResult
}

func runSeparatedConnectTarget(t *testing.T, ctx context.Context, component string) {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- benchworkload.ServeTCPEcho(ctx, listener) }()
	separatedWrite(t, component+".ready", time.Now())
	select {
	case <-ctx.Done():
		if err := <-done; err != nil {
			t.Error(err)
		}
	case err := <-done:
		t.Fatalf("connect echo target stopped: %v", err)
	}
}

func connectLoadClient(t *testing.T, ctx context.Context) (*clientstate.Database, *clientauth.Client) {
	t.Helper()
	state, err := clientstate.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	saveRuntimeOIDCSession(t, state, "https://control."+separatedDomain, testutil.PostgresURL(t), "routes."+separatedDomain)
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{ServerEndpoint: "https://control." + separatedDomain, State: state, HTTPClient: separatedHTTP(t), Diagnostics: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	return state, authenticated
}

func runSeparatedConnectPublishers(t *testing.T, ctx context.Context, count, shard int) {
	separatedWrite(t, separatedPublisherShardKey(shard, "concurrency"), runtimeLoadAdmission.PublisherConcurrency)
	if !separatedRead(t, ctx, "publish.start", nil) {
		return
	}
	state, authenticated := connectLoadClient(t, ctx)
	profile, err := state.Server(ctx, authenticated.ServerEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	person, err := authenticated.Authority.IdentityContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	services := make([]connectLoadService, count)
	publishCtx, stop := context.WithCancel(ctx)
	var publishers sync.WaitGroup
	defer func() { stop(); publishers.Wait() }()
	for _, index := range separatedPublisherIndexes(count, shard) {
		key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
		if err != nil {
			t.Fatal(err)
		}
		service, err := authenticated.Control.CreateService(ctx, person.PersonalTeamId, fmt.Sprintf("connect-%d", index), key)
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err := authenticated.Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, ServiceId: &service.Id, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled, Name: fmt.Sprintf("connect-load-%d", index)})
		if err != nil {
			t.Fatal(err)
		}
		native, identity, err := publisheridentity.EnrollNative(ctx, profile, authenticated.Control, authenticated.Authority, enrollment.EnrollmentKey)
		if err != nil {
			t.Fatal(err)
		}
		var quicConnector muxsession.Connector = muxsession.QUICConnector{TLSConfig: separatedRelayTLS(t), Config: muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}}}
		var tcp muxsession.Connector = muxsession.TLSYamuxConnector{TLSConfig: separatedRelayTLS(t)}
		transport := "quic"
		if index%2 == 0 {
			tcp = privateDisabledConnector()
		} else {
			quicConnector = privateDisabledConnector()
			transport = "tls-tcp"
		}
		ready, done := make(chan struct{}), make(chan error, 1)
		publishers.Go(func() {
			err := publisherservice.Publish(publishCtx, publisherservice.RunConfig{
				Control: authenticated.Control, State: profile, Access: native.Access, Identity: identity,
				ServiceID: service.Id, Target: "127.0.0.1:8080", StreamCapacity: 256,
				Metadata: controlv1.ServiceMetadata{Protocol: service.Protocol, TargetTls: service.TargetTls, TrustRevision: service.TrustRevision, PublisherPool: service.PublisherPool},
				Ready:    func() error { close(ready); return nil },
				Connect: func(ctx context.Context, bound *publisherservice.Bound, slot uint8) (publisherservice.SlotSession, error) {
					return bound.ConnectSlotWithTransports(ctx, slot, false, quicConnector, tcp)
				},
			})
			done <- err
			if err != nil {
				t.Errorf("connect publisher: %v", err)
			}
			if publishCtx.Err() == nil {
				t.Errorf("connect publisher stopped during workload: %v", err)
				failureCtx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = separatedCoordination(t).Put(failureCtx, "failure", fmt.Sprintf("connect publisher stopped: %v", err))
			}
		})
		select {
		case <-ready:
		case err := <-done:
			t.Fatalf("connect publisher stopped before ready: %v", err)
		case <-time.After(*runtimeLoadReadyTimeout):
			t.Fatal("connect publisher readiness deadline")
		}
		services[index] = connectLoadService{Service: service, Target: separatedPublisherComponents()[shard] + ":8080", Transport: transport}
	}
	separatedWrite(t, separatedPublisherShardKey(shard, "connect-ready"), services)
	if !separatedRead(t, ctx, "connect.publishers.stop", nil) {
		return
	}
	stop()
	publishers.Wait()
	separatedWrite(t, separatedPublisherShardKey(shard, "connect-stopped"), !t.Failed())
	<-ctx.Done()
}

func runSeparatedConnect(t *testing.T, database *sql.DB, count, rate int, duration time.Duration) {
	separatedWrite(t, "publish.start", true)
	services := make([]connectLoadService, count)
	for shard := range separatedPublisherComponents() {
		var result []connectLoadService
		separatedWait(t, separatedPublisherShardKey(shard, "connect-ready"), time.Duration(count)**runtimeLoadReadyTimeout, &result)
		for index, service := range result {
			if service.Service.Id != "" {
				services[index] = service
			}
		}
	}
	for _, service := range services {
		if service.Service.Id == "" {
			t.Fatal("missing connect service")
		}
	}
	separatedWrite(t, "connect.services", services)
	var startup benchworkload.Histogram
	for index := 1; index <= 4; index++ {
		var result benchworkload.Histogram
		separatedWait(t, fmt.Sprintf("visitor-%d.connect-ready", index), time.Duration(count)*35*time.Second, &result)
		if err := startup.Merge(result); err != nil {
			t.Fatal(err)
		}
	}
	separatedResult(t, "connect-startup", startup)
	var owners, claims, claimRelays, readyPublisherConnections, relays int
	if err := database.QueryRowContext(t.Context(), `SELECT count(DISTINCT pair.id),count(*),count(DISTINCT lease.relay_service_id)
		FROM control.connector_peer_pairs pair JOIN control.connector_peer_pair_leg_claims claim ON claim.pair_id=pair.id
		JOIN control.relay_leases lease ON lease.relay_id=claim.relay_id AND lease.relay_run_id=claim.relay_run_id AND lease.relay_lease_revision=claim.relay_lease_revision AND lease.lease_expires_at>now()
		WHERE pair.publisher_prepared_until>now() AND pair.expires_at>now() AND claim.confirmed_until>now()`).Scan(&owners, &claims, &claimRelays); err != nil || owners != count || claims != count*2 || claimRelays != 2 {
		t.Fatalf("connector owners=%d claims=%d relay services=%d: %v", owners, claims, claimRelays, err)
	}
	if err := database.QueryRowContext(t.Context(), `SELECT count(*), count(DISTINCT relay_service_id) FROM control.service_connection_slots WHERE state='ready' AND session_open`).Scan(&readyPublisherConnections, &relays); err != nil || readyPublisherConnections != count*2 || relays != 2 {
		t.Fatalf("publisher connections=%d relays=%d: %v", readyPublisherConnections, relays, err)
	}
	separatedResult(t, "connect-configuration", struct {
		Services, RequestsPerSecond, Workers, Queue, PayloadBytes int
		Duration                                                  time.Duration
	}{count, rate, *runtimeLoadWorkers, *runtimeLoadQueue, *connectLoadPayloadBytes, duration})
	for sequence, name := range []string{"direct-fresh", "connect-fresh", "direct-reused", "connect-reused"} {
		phase := connectLoadPhase{Name: name, Start: time.Now().Add(time.Second), Duration: duration, Direct: strings.HasPrefix(name, "direct"), Reuse: strings.HasSuffix(name, "reused")}
		// reused sockets are prepared before the timestamp is chosen, keeping setup
		// and offered scheduling delay out of the steady-state measurement.
		if phase.Reuse {
			separatedWrite(t, fmt.Sprintf("connect.prepare-%d", sequence), phase)
			for index := 1; index <= 4; index++ {
				separatedWait(t, fmt.Sprintf("%s.visitor-%d.prepared", name, index), 2*time.Minute, nil)
			}
			phase.Start = time.Now().Add(time.Second)
		}
		before := separatedCapture(t, database, name+"-before")
		separatedWrite(t, fmt.Sprintf("connect.phase-%d", sequence), phase)
		var results []connectLoadResult
		for index := 1; index <= 4; index++ {
			var result connectLoadResult
			separatedWait(t, fmt.Sprintf("%s.visitor-%d", name, index), duration+15*time.Second, &result)
			results = append(results, result)
		}
		after := separatedCapture(t, database, name+"-after")
		separatedReportResources(t, name, before, after)
		assertSeparatedNoMemoryLimitEvents(t, name, before, after)
		assertSeparatedNoRejections(t, name, before, after)
		reportConnectLoad(t, name, results)
	}
	separatedWrite(t, "connect.phase-4", connectLoadPhase{Done: true})
	for index := 1; index <= 4; index++ {
		var clean bool
		separatedWait(t, fmt.Sprintf("visitor-%d.connect-stopped", index), 30*time.Second, &clean)
		if !clean {
			t.Errorf("visitor-%d failed connector shutdown", index)
		}
	}
	separatedWrite(t, "connect.publishers.stop", true)
	for shard := range separatedPublisherComponents() {
		var clean bool
		separatedWait(t, separatedPublisherShardKey(shard, "connect-stopped"), 30*time.Second, &clean)
		if !clean {
			t.Errorf("publisher shard %d failed shutdown", shard)
		}
	}
	if runtimeEarlyFault(*runtimeLoadScenario) {
		separatedWrite(t, "fault.release", true)
		separatedWait(t, "fault.restored", 30*time.Second, nil)
	}
	var openRuns, liveOwners int
	// native replay fences remain after process shutdown. they cannot serve
	// through a closed publisher run and are not active ingress reservations.
	if err := database.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM control.service_runs WHERE closed_at IS NULL),
		(SELECT count(*) FROM control.connector_peer_pairs pair JOIN control.service_runs run ON run.id=pair.service_run_id WHERE run.closed_at IS NULL AND pair.expires_at>now() AND pair.publisher_prepared_until>now())`).Scan(&openRuns, &liveOwners); err != nil || openRuns != 0 || liveOwners != 0 {
		t.Errorf("connect cleanup retained runs=%d live owners=%d: %v", openRuns, liveOwners, err)
	}
	separatedResult(t, "connect-cleanup", map[string]int{"open_runs": openRuns, "live_native_owners": liveOwners})
	for _, ingress := range separatedIngresses() {
		separatedWrite(t, ingress+".stop", true)
	}
	for _, ingress := range separatedIngresses() {
		separatedWait(t, ingress+".stopped", 35*time.Second, nil)
	}
}

func reportConnectLoad(t *testing.T, name string, results []connectLoadResult) {
	t.Helper()
	var summary benchworkload.VisitorResult
	var setup benchworkload.Histogram
	cohorts := make(map[string]benchworkload.VisitorResult)
	var actual, first, scheduled []time.Duration
	for _, result := range results {
		if err := summary.Merge(result.Summary); err != nil {
			t.Fatal(err)
		}
		if err := setup.Merge(result.Setup); err != nil {
			t.Fatal(err)
		}
		for transport, value := range result.Cohorts {
			cohort := cohorts[transport]
			if err := cohort.Merge(value); err != nil {
				t.Fatal(err)
			}
			cohorts[transport] = cohort
		}
		for _, row := range result.Requests {
			if row.Error != "" {
				continue
			}
			actual = append(actual, row.Duration-row.QueueDelay)
			scheduled = append(scheduled, row.Duration)
			first = append(first, row.FirstByte.Sub(row.Started))
		}
	}
	separatedResult(t, name+"-summary", summary)
	separatedResult(t, name+"-cohorts", cohorts)
	separatedResult(t, name+"-setup", setup)
	separatedResult(t, name+"-visitors", results)
	exact := func(samples []time.Duration) map[string]float64 {
		slices.Sort(samples)
		values := make(map[string]float64)
		if len(samples) == 0 {
			return values
		}
		var total time.Duration
		for _, sample := range samples {
			total += sample
		}
		values["mean_ms"] = float64(total) / float64(len(samples)) / float64(time.Millisecond)
		for _, percentile := range []int{50, 95, 99} {
			values[fmt.Sprintf("p%d_ms", percentile)] = float64(exactLatencyPercentile(samples, percentile)) / float64(time.Millisecond)
		}
		return values
	}
	separatedResult(t, name+"-latency", map[string]any{"samples": len(actual), "request": exact(actual), "first_response_byte": exact(first), "scheduled": exact(scheduled)})
	t.Logf("connect_load phase=%s success=%d failure=%d missed=%d queue_expired=%d request=%v first_response_byte=%v", name, summary.Successes, summary.Failures, summary.Missed, summary.QueueExpired, exact(actual), exact(first))
	var expected int
	for index := range 4 {
		rate := benchworkload.Assignment(*runtimeLoadRPS, 4, index)
		expected += int((time.Duration(rate)**runtimeLoadDuration + time.Second - 1) / time.Second)
	}
	if err := summary.Err(); err != nil || summary.Scheduled != expected || len(actual) != summary.Successes {
		t.Errorf("%s: %v; failures=%+v", name, err, summary.FailuresSample)
		t.Errorf("scheduled=%d expected=%d latency samples=%d successes=%d", summary.Scheduled, expected, len(actual), summary.Successes)
	}
}

func runSeparatedConnectVisitor(t *testing.T, ctx context.Context, component string, rate int) {
	var services []connectLoadService
	if !separatedRead(t, ctx, "connect.services", &services) {
		return
	}
	index, _ := strconv.Atoi(strings.TrimPrefix(component, "visitor-"))
	state, _ := connectLoadClient(t, ctx)
	var local, direct []string
	cohortByAddress := make(map[string]string)
	var startup benchworkload.Histogram
	var processes []*integrationBinaryProcess
	for serviceIndex := index - 1; serviceIndex < len(services); serviceIndex += 4 {
		service := services[serviceIndex]
		started := time.Now()
		address := unusedTCPAddress(t)
		var output synchronizedBuffer
		process := &integrationBinaryProcess{}
		command := exec.Command("/artifacts/tnl",
			"--no-config", "--no-telemetry", "connect", service.Service.Id, "--server=https://control."+separatedDomain,
			"--state-dir="+state.Root(), "--listen="+address, "--output=json")
		command.Dir, command.Env = t.TempDir(), connectLoadEnvironment(t)
		command.Stdout, command.Stderr = &output, &process.output
		owner, err := startOwnedCommand(command, nil)
		if err != nil {
			t.Fatal(err)
		}
		process.commandOwner = owner
		t.Cleanup(func() { stopIntegrationBinaryProcess(t, process) })
		waitForIntegrationCondition(t, 35*time.Second, func(context.Context) (bool, error) {
			select {
			case <-process.done:
				t.Fatalf("tnl connect stopped before ready: %v\n%s", process.result(), process.output.String())
			default:
			}
			var ready struct {
				ServiceID string `json:"service_id"`
				Host      string `json:"host"`
				Port      int    `json:"port"`
			}
			if json.Unmarshal([]byte(output.String()), &ready) != nil {
				return false, nil
			}
			if ready.ServiceID != service.Service.Id || net.JoinHostPort(ready.Host, strconv.Itoa(ready.Port)) != address {
				t.Fatal("tnl connect returned another service or listener")
			}
			return true, nil
		})
		startup.Observe(time.Since(started))
		processes = append(processes, process)
		local, direct = append(local, address), append(direct, service.Target)
		cohortByAddress[address], cohortByAddress[service.Target] = service.Transport, service.Transport
	}
	separatedWrite(t, component+".connect-ready", startup)
	for sequence := 0; ; sequence++ {
		var phase connectLoadPhase
		visitor := &benchworkload.TCPVisitor{PayloadBytes: *connectLoadPayloadBytes}
		workers := benchworkload.Assignment(*runtimeLoadWorkers, 4, index-1)
		var setup benchworkload.Histogram
		if sequence == 2 || sequence == 3 {
			if !separatedRead(t, ctx, fmt.Sprintf("connect.prepare-%d", sequence), &phase) {
				return
			}
			addresses := local
			if phase.Direct {
				addresses = direct
			}
			var err error
			setup, err = visitor.Prepare(ctx, addresses, workers)
			if err != nil {
				t.Fatal(err)
			}
			separatedWrite(t, phase.Name+"."+component+".prepared", true)
		}
		if !separatedRead(t, ctx, fmt.Sprintf("connect.phase-%d", sequence), &phase) {
			_ = visitor.Close()
			return
		}
		if phase.Done {
			break
		}
		addresses := local
		if phase.Direct {
			addresses = direct
		}
		result := connectLoadResult{Setup: setup, Cohorts: make(map[string]benchworkload.VisitorResult)}
		var err error
		result.Summary, err = visitor.Run(ctx, benchworkload.VisitorConfig{Rate: benchworkload.Assignment(rate, 4, index-1), Workers: workers,
			QueueSlots: benchworkload.Assignment(*runtimeLoadQueue, 4, index-1), Start: phase.Start.Add(time.Duration(index-1) * time.Second / time.Duration(rate)), Duration: phase.Duration,
			OnResult: func(row benchworkload.RequestResult) {
				result.Requests = append(result.Requests, row)
				cohort := result.Cohorts[cohortByAddress[row.URL]]
				cohort.Scheduled++
				cohort.Observe(row)
				result.Cohorts[cohortByAddress[row.URL]] = cohort
			}}, addresses)
		if err != nil {
			t.Error(err)
		}
		if err := visitor.Close(); err != nil {
			t.Error(err)
		}
		separatedWrite(t, phase.Name+"."+component, result)
	}
	for _, process := range processes {
		stopIntegrationBinaryProcess(t, process)
	}
	separatedWrite(t, component+".connect-stopped", !t.Failed())
	<-ctx.Done()
}

func connectLoadEnvironment(t *testing.T) []string {
	t.Helper()
	var roots []byte
	for _, name := range []string{"roots.pem", "route-roots.pem"} {
		data, err := os.ReadFile(filepath.Join(separatedDirectory, name))
		if err != nil {
			t.Fatal(err)
		}
		roots = append(append(roots, data...), '\n')
	}
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, roots, 0600); err != nil {
		t.Fatal(err)
	}
	environment := slices.DeleteFunc(os.Environ(), func(value string) bool {
		return strings.HasPrefix(value, "SSL_CERT_FILE=") || strings.HasPrefix(value, "SSL_CERT_DIR=")
	})
	return append(environment, "SSL_CERT_FILE="+path, "SSL_CERT_DIR="+filepath.Dir(path))
}
