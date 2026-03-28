package tailtransport

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/processmetrics"
	"github.com/0xcadams/tnl/internal/tailbench"
	"tailscale.com/derp/derpserver"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	capacityOptIn      = "TNL_TEST_TAILCAT_CAPACITY"
	defaultRouteCounts = "1,10,100,500,1000"
	operationTimeout   = 30 * time.Second
	settleTime         = 250 * time.Millisecond
)

type capacityConfig struct {
	routeCounts  []int
	parallel     int
	transferSize int
	expectedPath string
}

type benchmarkLease struct {
	server *Server
	dialer *Dialer
	conn   net.Conn
}

func BenchmarkTailcatCapacity(b *testing.B) {
	if os.Getenv(capacityOptIn) != "1" {
		b.Skipf("set %s=1 to run the Tailcat capacity benchmark", capacityOptIn)
	}
	config, err := readCapacityConfig()
	if err != nil {
		b.Fatal(err)
	}
	region, derp := runTestDERPWithServer(b)

	for _, routeCount := range config.routeCounts {
		b.Run(fmt.Sprintf("routes_%d", routeCount), func(b *testing.B) {
			if b.N != 1 {
				b.Fatalf("capacity benchmark requires -benchtime=1x; b.N=%d", b.N)
			}
			runCapacityTier(b, config, region, derp, routeCount)
		})
	}
}

func BenchmarkTailcatChurn(b *testing.B) {
	if os.Getenv(capacityOptIn) != "1" {
		b.Skipf("set %s=1 to run the Tailcat churn benchmark", capacityOptIn)
	}
	parallel, err := readBenchmarkParallel()
	if err != nil {
		b.Fatal(err)
	}
	region := runTestDERP(b)
	before := settledResources()
	startup := make([]time.Duration, b.N)
	shutdown := make([]time.Duration, b.N)

	err = runParallel(b.N, parallel, func(index int) error {
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		startedAt := time.Now()
		lease, err := startBenchmarkLease(ctx, region)
		startup[index] = time.Since(startedAt)
		if err != nil {
			return err
		}
		defer lease.forceClose()
		lease.conn, _, err = tailbench.OpenEchoStream(ctx, lease.dialer.Open)
		if err != nil {
			return err
		}
		closedAt := time.Now()
		err = lease.shutdown(ctx)
		shutdown[index] = time.Since(closedAt)
		return err
	})
	if err != nil {
		b.Fatal(err)
	}
	after := settledResources()
	reportLatency(b, "startup", startup)
	reportLatency(b, "shutdown", shutdown)
	reportResiduals(b, "", before, after)
	enforceBudgets(b, b.N, before, after, after, startup, nil, shutdown, 32*1024*1024)
}

func runCapacityTier(b *testing.B, config capacityConfig, region *tailcfg.DERPRegion, derp *derpserver.Server, routeCount int) {
	before := settledResources()
	leases := make([]*benchmarkLease, routeCount)
	startup := make([]time.Duration, routeCount)
	firstByte := make([]time.Duration, routeCount)
	shutdown := make([]time.Duration, routeCount)
	defer func() {
		b.Logf("cleaning up %d routes", routeCount)
		_ = runParallel(routeCount, config.parallel, func(index int) error {
			if leases[index] != nil {
				leases[index].forceClose()
			}
			return nil
		})
	}()

	b.Logf("starting %d routes", routeCount)
	err := runParallel(routeCount, config.parallel, func(index int) error {
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		startedAt := time.Now()
		lease, err := startBenchmarkLease(ctx, region)
		startup[index] = time.Since(startedAt)
		leases[index] = lease
		return err
	})
	if err != nil {
		logDERPDiagnostics(b, derp, "startup failure")
		b.Fatal(err)
	}
	logDERPDiagnostics(b, derp, "started")
	if config.expectedPath != "any" {
		b.Logf("preparing %s path for %d routes", config.expectedPath, routeCount)
		pathReady := make([]time.Duration, routeCount)
		err = runParallel(routeCount, config.parallel, func(index int) error {
			startedAt := time.Now()
			_, err := observePath(leases[index].dialer, config.expectedPath)
			pathReady[index] = time.Since(startedAt)
			return err
		})
		if err != nil {
			logDERPDiagnostics(b, derp, "path preparation failure")
			b.Fatal(err)
		}
		reportLatency(b, "path_ready", pathReady)
	}
	b.Logf("opening %d streams", routeCount)
	idle := processmetrics.Read()

	err = runParallel(routeCount, config.parallel, func(index int) error {
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		conn, latency, err := tailbench.OpenEchoStream(ctx, leases[index].dialer.Open)
		leases[index].conn = conn
		firstByte[index] = latency
		return err
	})
	if err != nil {
		logDERPDiagnostics(b, derp, "stream open failure")
		b.Fatal(err)
	}
	active := processmetrics.Read()
	b.Logf("probing path and transferring %d bytes per stream", config.transferSize)
	directRoutes := 0
	if config.expectedPath == "any" {
		var directMu sync.Mutex
		err = runParallel(routeCount, config.parallel, func(index int) error {
			direct, err := observePath(leases[index].dialer, "any")
			if direct {
				directMu.Lock()
				directRoutes++
				directMu.Unlock()
			}
			return err
		})
		if err != nil {
			logDERPDiagnostics(b, derp, "path probe failure")
			b.Fatal(err)
		}
	} else if config.expectedPath == "direct" {
		directRoutes = routeCount
	}

	transferred := int64(routeCount * config.transferSize)
	transferStarted := time.Now()
	err = runParallel(routeCount, config.parallel, func(index int) error {
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		if deadline, ok := ctx.Deadline(); ok {
			_ = leases[index].conn.SetDeadline(deadline)
		}
		err := tailbench.RoundTripBytes(leases[index].conn, config.transferSize)
		_ = leases[index].conn.SetDeadline(time.Time{})
		return err
	})
	transferTime := time.Since(transferStarted)
	if err != nil {
		logDERPDiagnostics(b, derp, "transfer failure")
		b.Fatal(err)
	}

	b.Logf("shutting down %d routes", routeCount)
	err = runParallel(routeCount, config.parallel, func(index int) error {
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		closedAt := time.Now()
		err := leases[index].shutdown(ctx)
		shutdown[index] = time.Since(closedAt)
		return err
	})
	if err != nil {
		logDERPDiagnostics(b, derp, "shutdown failure")
		b.Fatal(err)
	}
	for index := range leases {
		leases[index] = nil
	}
	after := settledResources()

	reportLatency(b, "startup", startup)
	reportLatency(b, "first_byte", firstByte)
	reportLatency(b, "shutdown", shutdown)
	reportPerRoute(b, "idle", before, idle, routeCount)
	reportPerRoute(b, "active", before, active, routeCount)
	reportResiduals(b, "", before, after)
	b.ReportMetric(float64(transferred)/(1024*1024)/transferTime.Seconds(), "MiB/s")
	b.ReportMetric(float64(directRoutes), "direct_routes")
	b.ReportMetric(float64(routeCount-directRoutes), "derp_routes")
	residualBudget := int64(32*1024*1024 + routeCount*512*1024)
	enforceBudgets(b, routeCount, before, idle, after, startup, firstByte, shutdown, residualBudget)
}

func startBenchmarkLease(ctx context.Context, region *tailcfg.DERPRegion) (*benchmarkLease, error) {
	clientKey := key.NewNode()
	server, endpoint, err := startTestServer(ctx, region, clientKey.Public(), func(conn net.Conn) {
		_, _ = io.Copy(conn, conn)
	})
	if err != nil {
		return nil, err
	}
	dialer, err := startTestDialer(ctx, region, endpoint, clientKey)
	if err != nil {
		server.Close()
		return nil, err
	}
	return &benchmarkLease{server: server, dialer: dialer}, nil
}

func (l *benchmarkLease) shutdown(ctx context.Context) error {
	var errs []error
	if l.conn != nil {
		errs = append(errs, tailbench.CloseEchoStream(ctx, l.conn))
		l.conn = nil
	}
	errs = append(errs, l.dialer.Drain(ctx), l.server.Drain(ctx), l.dialer.Close(), l.server.Close())
	return errors.Join(errs...)
}

func (l *benchmarkLease) forceClose() {
	if l.conn != nil {
		_ = l.conn.Close()
		l.conn = nil
	}
	if l.dialer != nil {
		_ = l.dialer.Close()
	}
	if l.server != nil {
		_ = l.server.Close()
	}
}

func runParallel(count, parallel int, run func(int) error) error {
	jobs := make(chan int)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var failuresMu sync.Mutex
	var failures []error
	var workers sync.WaitGroup
	for range min(count, parallel) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				var index int
				var ok bool
				select {
				case <-ctx.Done():
					return
				case index, ok = <-jobs:
					if !ok {
						return
					}
				}
				if err := run(index); err != nil {
					failuresMu.Lock()
					failures = append(failures, fmt.Errorf("operation %d: %w", index, err))
					failuresMu.Unlock()
					cancel()
					return
				}
			}
		}()
	}

sendJobs:
	for index := range count {
		select {
		case <-ctx.Done():
			break sendJobs
		case jobs <- index:
		}
	}
	close(jobs)
	workers.Wait()
	return errors.Join(failures...)
}

type pathProber interface {
	DiscoPing(context.Context) (*ipnstate.PingResult, error)
}

func observePath(dialer *Dialer, expected string) (bool, error) {
	prober, ok := dialer.client.(pathProber)
	if !ok {
		return false, errors.New("tailcat client does not support path probing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		result, err := prober.DiscoPing(ctx)
		if err != nil {
			return false, err
		}
		direct := result.Endpoint != ""
		if expected == "any" || expected == "direct" && direct || expected == "derp" && !direct && result.DERPRegionID != 0 {
			return direct, nil
		}
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("expected %s path: %w", expected, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func readCapacityConfig() (capacityConfig, error) {
	counts, err := parsePositiveInts(envOr("TNL_TEST_TAILCAT_ROUTES", defaultRouteCounts))
	if err != nil {
		return capacityConfig{}, fmt.Errorf("TNL_TEST_TAILCAT_ROUTES: %w", err)
	}
	parallel, err := readBenchmarkParallel()
	if err != nil {
		return capacityConfig{}, fmt.Errorf("TNL_TEST_TAILCAT_PARALLEL: %w", err)
	}
	transferSize, err := parsePositiveInt(envOr("TNL_TEST_TAILCAT_BYTES", strconv.Itoa(64*1024)))
	if err != nil {
		return capacityConfig{}, fmt.Errorf("TNL_TEST_TAILCAT_BYTES: %w", err)
	}
	expectedPath := envOr("TNL_TEST_TAILCAT_PATH", "any")
	if expectedPath != "any" && expectedPath != "direct" && expectedPath != "derp" {
		return capacityConfig{}, errors.New("TNL_TEST_TAILCAT_PATH must be any, direct, or derp")
	}
	return capacityConfig{counts, parallel, transferSize, expectedPath}, nil
}

func readBenchmarkParallel() (int, error) {
	parallel, err := parsePositiveInt(envOr("TNL_TEST_TAILCAT_PARALLEL", strconv.Itoa(min(8, runtime.GOMAXPROCS(0)))))
	if err != nil {
		return 0, fmt.Errorf("TNL_TEST_TAILCAT_PARALLEL: %w", err)
	}
	return parallel, nil
}

func parsePositiveInts(value string) ([]int, error) {
	parts := strings.Split(value, ",")
	values := make([]int, len(parts))
	for index, part := range parts {
		value, err := parsePositiveInt(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		values[index] = value
	}
	return values, nil
}

func parsePositiveInt(value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("%q is not a positive integer", value)
	}
	return parsed, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func settledResources() processmetrics.Snapshot {
	runtime.GC()
	time.Sleep(settleTime)
	runtime.GC()
	return processmetrics.Read()
}

func logDERPDiagnostics(b *testing.B, server *derpserver.Server, phase string) {
	b.Helper()
	variables, ok := server.ExpVar(false).(interface{ Get(string) expvar.Var })
	if !ok {
		b.Logf("DERP %s: metrics unavailable", phase)
		return
	}
	value := func(name string) string {
		variable := variables.Get(name)
		if variable == nil {
			return "unavailable"
		}
		return variable.String()
	}
	b.Logf("DERP %s: connections=%s accepts=%s packets_sent=%s packets_received=%s write_timeouts=%s drops=%s",
		phase,
		value("gauge_current_connections"),
		value("accepts"),
		value("packets_sent"),
		value("packets_received"),
		value("sclient_write_timeouts"),
		expvarString("derp_packets_dropped"),
	)
}

func expvarString(name string) string {
	variable := expvar.Get(name)
	if variable == nil {
		return "unavailable"
	}
	if writer, ok := variable.(interface {
		WritePrometheus(io.Writer, string)
	}); ok {
		var output strings.Builder
		writer.WritePrometheus(&output, name)
		var values []string
		for _, line := range strings.Split(output.String(), "\n") {
			if line != "" && !strings.HasPrefix(line, "#") && !strings.HasSuffix(line, " 0") {
				values = append(values, line)
			}
		}
		if len(values) == 0 {
			return "none"
		}
		return strings.Join(values, ", ")
	}
	return variable.String()
}

func reportLatency(b *testing.B, name string, samples []time.Duration) {
	b.Helper()
	for _, percentile := range []int{50, 95, 99} {
		b.ReportMetric(float64(durationPercentile(samples, percentile))/float64(time.Millisecond), fmt.Sprintf("%s_p%d_ms", name, percentile))
	}
}

func durationPercentile(samples []time.Duration, percentile int) time.Duration {
	ordered := slices.Clone(samples)
	slices.Sort(ordered)
	index := max(0, int(math.Ceil(float64(percentile*len(ordered))/100))-1)
	return ordered[index]
}

func reportPerRoute(b *testing.B, name string, before, after processmetrics.Snapshot, routes int) {
	b.Helper()
	b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/float64(routes), name+"_heap_B/route")
	b.ReportMetric(float64(after.Sys-before.Sys)/float64(routes), name+"_sys_B/route")
	b.ReportMetric(float64(after.Goroutines-before.Goroutines)/float64(routes), name+"_goroutines/route")
	if before.OpenFDs >= 0 && after.OpenFDs >= 0 {
		b.ReportMetric(float64(after.OpenFDs-before.OpenFDs)/float64(routes), name+"_fds/route")
	}
	if before.RSS >= 0 && after.RSS >= 0 {
		b.ReportMetric(float64(after.RSS-before.RSS)/float64(routes), name+"_rss_B/route")
	}
}

func reportResiduals(b *testing.B, prefix string, before, after processmetrics.Snapshot) {
	b.Helper()
	b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc), prefix+"residual_heap_B")
	b.ReportMetric(float64(after.Sys-before.Sys), prefix+"residual_sys_B")
	b.ReportMetric(float64(after.Goroutines-before.Goroutines), prefix+"residual_goroutines")
	b.ReportMetric(after.UserCPU-before.UserCPU, prefix+"user_cpu_seconds")
	if before.OpenFDs >= 0 && after.OpenFDs >= 0 {
		b.ReportMetric(float64(after.OpenFDs-before.OpenFDs), prefix+"residual_fds")
	}
	if before.RSS >= 0 && after.RSS >= 0 {
		b.ReportMetric(float64(after.RSS-before.RSS), prefix+"residual_rss_B")
	}
}

func enforceBudgets(b *testing.B, routes int, before, ready, after processmetrics.Snapshot, startup, firstByte, shutdown []time.Duration, residualHeapBudget int64) {
	b.Helper()
	if durationPercentile(startup, 95) > 15*time.Second {
		b.Errorf("startup p95 exceeds 15s")
	}
	if len(firstByte) != 0 && durationPercentile(firstByte, 95) > 2*time.Second {
		b.Errorf("first-byte p95 exceeds 2s")
	}
	if durationPercentile(shutdown, 95) > 5*time.Second {
		b.Errorf("shutdown p95 exceeds 5s")
	}
	if delta := after.HeapAlloc - before.HeapAlloc; delta > residualHeapBudget {
		b.Errorf("residual heap is %d bytes; budget is %d bytes", delta, residualHeapBudget)
	}
	if delta := after.Goroutines - before.Goroutines; delta > 16 {
		b.Errorf("residual goroutines is %d; budget is 16", delta)
	}
	if before.OpenFDs >= 0 && after.OpenFDs-before.OpenFDs > 16 {
		b.Errorf("residual file descriptors is %d; budget is 16", after.OpenFDs-before.OpenFDs)
	}
	if routes >= 10 && (ready.HeapAlloc-before.HeapAlloc)/int64(routes) > 8*1024*1024 {
		b.Errorf("idle heap exceeds 8 MiB per route")
	}
}
