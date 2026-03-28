package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/0xcadams/tnl/internal/processmetrics"
	"github.com/0xcadams/tnl/internal/tailbench"
	"github.com/0xcadams/tnl/internal/tailtransport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const clientOperationTimeout = 30 * time.Second

func runClient(ctx context.Context, token string, region *tailcfg.DERPRegion, serverURL string) (tailbench.ClientRunResult, error) {
	serverURL = strings.TrimRight(serverURL, "/")
	if serverURL == "" {
		return tailbench.ClientRunResult{}, errors.New("TNL_TAILBENCH_SERVER_URL is required")
	}
	routeCount, err := requiredPositiveEnv("TNL_TAILBENCH_ROUTES")
	if err != nil {
		return tailbench.ClientRunResult{}, err
	}
	if routeCount > 500 {
		return tailbench.ClientRunResult{}, errors.New("TNL_TAILBENCH_ROUTES must not exceed 500")
	}
	parallelism := envInt("TNL_TAILBENCH_PARALLEL", 8)
	transferSize := envInt("TNL_TAILBENCH_BYTES", 64*1024)
	if parallelism <= 0 || transferSize <= 0 {
		return tailbench.ClientRunResult{}, errors.New("client parallelism and transfer size must be positive")
	}
	if startText := os.Getenv("TNL_TAILBENCH_START_UNIX"); startText != "" {
		startUnix, err := strconv.ParseInt(startText, 10, 64)
		if err != nil {
			return tailbench.ClientRunResult{}, fmt.Errorf("TNL_TAILBENCH_START_UNIX: %w", err)
		}
		if err := waitUntil(ctx, time.Unix(startUnix, 0)); err != nil {
			return tailbench.ClientRunResult{}, err
		}
	}

	result := tailbench.ClientRunResult{RouteCount: routeCount, ClientBefore: processmetrics.Read(), StartedAt: time.Now().UTC()}
	keys := make([]key.NodePrivate, routeCount)
	publicKeys := make([]string, routeCount)
	for index := range routeCount {
		keys[index] = key.NewNode()
		publicKeys[index] = keys[index].Public().String()
	}
	remote := tailbench.NewAgentClient(serverURL, token, 20*time.Minute)
	created, err := remote.Create(publicKeys)
	if err != nil {
		return result, err
	}
	remoteActive := true
	defer func() {
		if remoteActive {
			_, _ = remote.Close()
		}
	}()
	result.WorkerBefore = created.Before
	result.WorkerReady = created.Ready
	if len(created.Endpoints) != routeCount {
		return result, fmt.Errorf("worker returned %d endpoints; want %d", len(created.Endpoints), routeCount)
	}
	metricsOK, memoryLimit, err := verifyWorkerMetrics(ctx, serverURL, routeCount)
	if err != nil {
		return result, err
	}
	result.WorkerMetricsOK = metricsOK
	result.WorkerMemoryLimit = memoryLimit

	dialers := make([]*tailtransport.Dialer, routeCount)
	connections := make([]net.Conn, routeCount)
	defer func() {
		_ = parallel(routeCount, parallelism, func(index int) error {
			if connections[index] != nil {
				_ = connections[index].Close()
			}
			if dialers[index] != nil {
				_ = dialers[index].Close()
			}
			return nil
		})
	}()
	profiles := map[string]*tailcfg.DERPRegion{tailbench.RelayProfile: region}
	startup := make([]time.Duration, routeCount)
	err = parallel(routeCount, parallelism, func(index int) error {
		dialer, err := tailtransport.NewDialer(tailtransport.DialerConfig{
			Endpoint: created.Endpoints[index],
			Profiles: profiles,
			Key:      keys[index],
			Logf:     logger.Discard,
		})
		if err != nil {
			return err
		}
		dialers[index] = dialer
		operationCtx, cancel := context.WithTimeout(ctx, clientOperationTimeout)
		defer cancel()
		started := time.Now()
		err = dialer.Start(operationCtx)
		startup[index] = time.Since(started)
		return err
	})
	if err != nil {
		return result, fmt.Errorf("start client routes: %w", err)
	}

	firstByte := make([]time.Duration, routeCount)
	err = parallel(routeCount, parallelism, func(index int) error {
		operationCtx, cancel := context.WithTimeout(ctx, clientOperationTimeout)
		defer cancel()
		conn, latency, err := tailbench.OpenEchoStream(operationCtx, dialers[index].Open)
		connections[index] = conn
		firstByte[index] = latency
		return err
	})
	if err != nil {
		return result, fmt.Errorf("open client streams: %w", err)
	}
	result.ClientReady = processmetrics.Read()

	transferStarted := time.Now()
	err = parallel(routeCount, parallelism, func(index int) error {
		operationCtx, cancel := context.WithTimeout(ctx, clientOperationTimeout)
		defer cancel()
		if deadline, ok := operationCtx.Deadline(); ok {
			_ = connections[index].SetDeadline(deadline)
		}
		err := tailbench.RoundTripBytes(connections[index], transferSize)
		_ = connections[index].SetDeadline(time.Time{})
		return err
	})
	transferDuration := time.Since(transferStarted)
	if err != nil {
		return result, fmt.Errorf("transfer client streams: %w", err)
	}

	shutdown := make([]time.Duration, routeCount)
	err = parallel(routeCount, parallelism, func(index int) error {
		operationCtx, cancel := context.WithTimeout(ctx, clientOperationTimeout)
		defer cancel()
		started := time.Now()
		streamErr := tailbench.CloseEchoStream(operationCtx, connections[index])
		connections[index] = nil
		drainErr := dialers[index].Drain(operationCtx)
		shutdown[index] = time.Since(started)
		return errors.Join(streamErr, drainErr)
	})
	if err != nil {
		return result, fmt.Errorf("close client routes: %w", err)
	}
	closed, err := remote.Close()
	if err != nil {
		return result, err
	}
	remoteActive = false
	if err := parallel(routeCount, parallelism, func(index int) error {
		err := dialers[index].Close()
		dialers[index] = nil
		return err
	}); err != nil {
		return result, fmt.Errorf("close client dialers: %w", err)
	}
	runtime.GC()
	runtime.GC()
	result.TransferBytes = int64(routeCount * transferSize)
	result.TransferDurationMS = transferDuration.Milliseconds()
	result.ThroughputMiB = float64(result.TransferBytes) / (1024 * 1024) / transferDuration.Seconds()
	result.StartupP95MS = percentile95(startup).Milliseconds()
	result.FirstByteP95MS = percentile95(firstByte).Milliseconds()
	result.ShutdownP95MS = percentile95(shutdown).Milliseconds()
	result.ClientAfter = processmetrics.Read()
	result.WorkerAfter = closed.After
	result.WorkerForcedCloses = closed.ForcedCloses
	result.WorkerDrainError = closed.DrainError
	result.FinishedAt = time.Now().UTC()
	return result, nil
}

func verifyWorkerMetrics(ctx context.Context, serverURL string, routeCount int) (bool, int64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/metrics", nil)
	if err != nil {
		return false, 0, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return false, 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("worker metrics: %s", response.Status)
	}
	values := make(map[string]float64)
	scanner := bufio.NewScanner(io.LimitReader(response.Body, 4<<20))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && (fields[0] == "tnl_worker_routes_active" || fields[0] == "go_gc_gomemlimit_bytes") {
			value, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				return false, 0, err
			}
			values[fields[0]] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return false, 0, err
	}
	memoryLimit := int64(values["go_gc_gomemlimit_bytes"])
	return int(values["tnl_worker_routes_active"]) == routeCount && memoryLimit > 0, memoryLimit, nil
}

func waitUntil(ctx context.Context, target time.Time) error {
	if delay := time.Until(target); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func requiredPositiveEnv(name string) (int, error) {
	value := os.Getenv(name)
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func percentile95(values []time.Duration) time.Duration {
	ordered := slices.Clone(values)
	slices.Sort(ordered)
	index := (95*len(ordered) + 99) / 100
	return ordered[index-1]
}
