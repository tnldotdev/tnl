package tailtransport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/processmetrics"
	"github.com/0xcadams/tnl/internal/tailbench"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func BenchmarkTailcatFly(b *testing.B) {
	if os.Getenv("TNL_TEST_TAILCAT_FLY") != "1" {
		b.Skip("set TNL_TEST_TAILCAT_FLY=1 to run the Fly benchmark")
	}
	config, err := readCapacityConfig()
	if err != nil {
		b.Fatal(err)
	}
	if config.expectedPath == "any" {
		b.Fatal("Fly benchmark requires TNL_TEST_TAILCAT_PATH=direct or derp")
	}
	regionID, err := parsePositiveInt(envOr("TNL_TEST_TAILCAT_DERP_REGION", "302"))
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	region, err := tailbench.PublicRegion(ctx, regionID)
	if err != nil {
		b.Fatal(err)
	}
	agentURL := os.Getenv("TNL_TEST_TAILCAT_AGENT_URL")
	agentToken := os.Getenv("TNL_TAILBENCH_TOKEN")
	if agentURL == "" || agentToken == "" {
		b.Fatal("TNL_TEST_TAILCAT_AGENT_URL and TNL_TAILBENCH_TOKEN are required")
	}
	agent := tailbench.NewAgentClient(agentURL, agentToken, 20*time.Minute)

	for _, routeCount := range config.routeCounts {
		if ok := b.Run(fmt.Sprintf("routes_%d", routeCount), func(b *testing.B) {
			if b.N != 1 {
				b.Fatalf("Fly benchmark requires -benchtime=1x; b.N=%d", b.N)
			}
			runFlyCapacityTier(b, config, region, agent, routeCount)
		}); !ok {
			return
		}
	}
}

func runFlyCapacityTier(b *testing.B, config capacityConfig, region *tailcfg.DERPRegion, agent *tailbench.AgentClient, routeCount int) {
	before := settledResources()
	keys := make([]key.NodePrivate, routeCount)
	publicKeys := make([]string, routeCount)
	for index := range routeCount {
		keys[index] = key.NewNode()
		publicKeys[index] = keys[index].Public().String()
	}

	b.Logf("starting %d Fly agent routes", routeCount)
	agentStarted := time.Now()
	remote, err := agent.Create(publicKeys)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(time.Since(agentStarted))/float64(time.Millisecond), "agent_ready_ms")
	remoteActive := true
	dialers := make([]*Dialer, routeCount)
	connections := make([]net.Conn, routeCount)
	defer func() {
		_ = runParallel(routeCount, config.parallel, func(index int) error {
			if connections[index] != nil {
				_ = connections[index].Close()
			}
			if dialers[index] != nil {
				_ = dialers[index].Close()
			}
			return nil
		})
		if remoteActive {
			_, _ = agent.Close()
		}
	}()
	if len(remote.Endpoints) != routeCount {
		b.Fatalf("agent returned %d endpoints; want %d", len(remote.Endpoints), routeCount)
	}

	startup := make([]time.Duration, routeCount)
	profiles := map[string]*tailcfg.DERPRegion{tailbench.RelayProfile: region}
	err = runParallel(routeCount, config.parallel, func(index int) error {
		endpoint := remote.Endpoints[index]
		dialer, err := NewDialer(DialerConfig{
			Endpoint: endpoint,
			Profiles: profiles,
			Key:      keys[index],
			Logf:     logger.Discard,
		})
		if err != nil {
			return err
		}
		dialers[index] = dialer
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		startedAt := time.Now()
		err = dialer.Start(ctx)
		startup[index] = time.Since(startedAt)
		return err
	})
	if err != nil {
		b.Fatal(err)
	}

	b.Logf("preparing %s path for %d routes", config.expectedPath, routeCount)
	pathReady := make([]time.Duration, routeCount)
	directPaths := make([]bool, routeCount)
	err = runParallel(routeCount, config.parallel, func(index int) error {
		startedAt := time.Now()
		direct, err := observePath(dialers[index], config.expectedPath)
		pathReady[index] = time.Since(startedAt)
		directPaths[index] = direct
		if config.expectedPath == "direct" && errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return err
	})
	if err != nil {
		b.Fatal(err)
	}

	b.Logf("opening %d streams", routeCount)
	firstByte := make([]time.Duration, routeCount)
	err = runParallel(routeCount, config.parallel, func(index int) error {
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		conn, latency, err := tailbench.OpenEchoStream(ctx, dialers[index].Open)
		connections[index] = conn
		firstByte[index] = latency
		return err
	})
	if err != nil {
		b.Fatal(err)
	}
	ready := processmetrics.Read()

	b.Logf("transferring %d bytes per stream", config.transferSize)
	transferStarted := time.Now()
	err = runParallel(routeCount, config.parallel, func(index int) error {
		deadline := time.Now().Add(operationTimeout)
		_ = connections[index].SetDeadline(deadline)
		err := tailbench.RoundTripBytes(connections[index], config.transferSize)
		_ = connections[index].SetDeadline(time.Time{})
		return err
	})
	transferTime := time.Since(transferStarted)
	if err != nil {
		b.Fatal(err)
	}

	b.Logf("closing %d local clients", routeCount)
	shutdown := make([]time.Duration, routeCount)
	err = runParallel(routeCount, config.parallel, func(index int) error {
		ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		startedAt := time.Now()
		connErr := tailbench.CloseEchoStream(ctx, connections[index])
		connections[index] = nil
		drainErr := dialers[index].Drain(ctx)
		shutdown[index] = time.Since(startedAt)
		return errors.Join(connErr, drainErr)
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("closing %d Fly agent routes", routeCount)
	agentShutdownStarted := time.Now()
	remoteClosed, err := agent.Close()
	if err != nil {
		b.Fatal(err)
	}
	agentShutdown := time.Since(agentShutdownStarted)
	if remoteClosed.DrainError != "" {
		b.Logf("agent force-closed %d routes: %s", remoteClosed.ForcedCloses, remoteClosed.DrainError)
	}
	remoteActive = false
	err = runParallel(routeCount, config.parallel, func(index int) error {
		err := dialers[index].Close()
		dialers[index] = nil
		return err
	})
	if err != nil {
		b.Fatal(err)
	}
	keys = nil
	publicKeys = nil
	after := settledResources()

	reportLatency(b, "startup", startup)
	reportLatency(b, "path_ready", pathReady)
	reportLatency(b, "first_byte", firstByte)
	reportLatency(b, "client_shutdown", shutdown)
	b.ReportMetric(float64(agentShutdown)/float64(time.Millisecond), "agent_shutdown_ms")
	reportPerRoute(b, "client_ready", before, ready, routeCount)
	reportResiduals(b, "", before, after)
	reportPerRoute(b, "agent", remote.Before, remote.Ready, routeCount)
	reportResiduals(b, "agent_", remote.Before, remoteClosed.After)
	directRoutes := 0
	for _, direct := range directPaths {
		if direct {
			directRoutes++
		}
	}
	b.ReportMetric(float64(routeCount*config.transferSize)/(1024*1024)/transferTime.Seconds(), "MiB/s")
	b.ReportMetric(float64(directRoutes), "direct_routes")
	b.ReportMetric(float64(routeCount-directRoutes), "derp_routes")
	b.ReportMetric(float64(remoteClosed.ForcedCloses), "agent_forced_closes")
	residualBudget := int64(32*1024*1024 + routeCount*512*1024)
	enforceBudgets(b, routeCount, before, ready, after, startup, firstByte, shutdown, residualBudget)
}
