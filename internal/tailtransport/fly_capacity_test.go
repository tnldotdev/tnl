package tailtransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

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
	agent := &flyAgent{
		url:   os.Getenv("TNL_TEST_TAILCAT_AGENT_URL"),
		token: os.Getenv("TNL_TAILBENCH_TOKEN"),
		http:  &http.Client{Timeout: 20 * time.Minute},
	}
	if agent.url == "" || agent.token == "" {
		b.Fatal("TNL_TEST_TAILCAT_AGENT_URL and TNL_TAILBENCH_TOKEN are required")
	}

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

func runFlyCapacityTier(b *testing.B, config capacityConfig, region *tailcfg.DERPRegion, agent *flyAgent, routeCount int) {
	before := settledResources()
	keys := make([]key.NodePrivate, routeCount)
	publicKeys := make([]string, routeCount)
	for index := range routeCount {
		keys[index] = key.NewNode()
		publicKeys[index] = keys[index].Public().String()
	}

	b.Logf("starting %d Fly agent routes", routeCount)
	agentStarted := time.Now()
	remote, err := agent.create(publicKeys)
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
			_, _ = agent.close()
		}
	}()
	if len(remote.Endpoints) != routeCount {
		b.Fatalf("agent returned %d endpoints; want %d", len(remote.Endpoints), routeCount)
	}

	startup := make([]time.Duration, routeCount)
	err = runParallel(routeCount, config.parallel, func(index int) error {
		endpoint := remote.Endpoints[index]
		dialer, err := NewDialer(DialerConfig{
			Endpoint: Endpoint{
				Version:         endpoint.Version,
				ServerPublicKey: endpoint.ServerPublicKey,
				RelayProfile:    endpoint.RelayProfile,
			},
			Profiles: map[string]*tailcfg.DERPRegion{tailbench.RelayProfile: region},
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
	err = runParallel(routeCount, config.parallel, func(index int) error {
		startedAt := time.Now()
		_, err := observePath(dialers[index], config.expectedPath)
		pathReady[index] = time.Since(startedAt)
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
		conn, latency, err := openBenchmarkStream(ctx, dialers[index])
		connections[index] = conn
		firstByte[index] = latency
		return err
	})
	if err != nil {
		b.Fatal(err)
	}
	ready := readResources()

	b.Logf("transferring %d bytes per stream", config.transferSize)
	transferStarted := time.Now()
	err = runParallel(routeCount, config.parallel, func(index int) error {
		deadline := time.Now().Add(operationTimeout)
		_ = connections[index].SetDeadline(deadline)
		err := roundTripBytes(connections[index], config.transferSize)
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
		connErr := connections[index].Close()
		connections[index] = nil
		drainErr := dialers[index].Drain(ctx)
		shutdown[index] = time.Since(startedAt)
		return errors.Join(connErr, drainErr)
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("closing %d Fly agent routes", routeCount)
	remoteClosed, err := agent.close()
	if err != nil {
		b.Fatal(err)
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
	reportLatency(b, "shutdown", shutdown)
	reportPerRoute(b, "client_ready", before, ready, routeCount)
	reportResiduals(b, before, after)
	reportAgentResources(b, remote.Before, remote.Ready, remoteClosed.After, routeCount)
	b.ReportMetric(float64(routeCount*config.transferSize)/(1024*1024)/transferTime.Seconds(), "MiB/s")
	b.ReportMetric(float64(routeCount), config.expectedPath+"_routes")
	residualBudget := int64(32*1024*1024 + routeCount*512*1024)
	enforceBudgets(b, routeCount, before, ready, after, startup, firstByte, shutdown, residualBudget)
}

type flyAgent struct {
	url   string
	token string
	http  *http.Client
}

func (a *flyAgent) create(keys []string) (tailbench.CreateRunResponse, error) {
	var response tailbench.CreateRunResponse
	err := a.request(http.MethodPost, tailbench.CreateRunRequest{ClientPublicKeys: keys}, &response)
	return response, err
}

func (a *flyAgent) close() (tailbench.CloseRunResponse, error) {
	var response tailbench.CloseRunResponse
	err := a.request(http.MethodDelete, nil, &response)
	return response, err
}

func (a *flyAgent) request(method string, body, response any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, a.url+"/v1/run", reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+a.token)
	request.Header.Set("Content-Type", "application/json")
	result, err := a.http.Do(request)
	if err != nil {
		return err
	}
	defer result.Body.Close()
	if result.StatusCode/100 != 2 {
		message, _ := io.ReadAll(io.LimitReader(result.Body, 4*1024))
		return fmt.Errorf("agent %s: %s: %s", method, result.Status, bytes.TrimSpace(message))
	}
	return json.NewDecoder(result.Body).Decode(response)
}

func reportAgentResources(b *testing.B, before, ready, after tailbench.Resources, routes int) {
	b.Helper()
	b.ReportMetric(float64(int64(ready.HeapAlloc)-int64(before.HeapAlloc))/float64(routes), "agent_heap_B/route")
	b.ReportMetric(float64(int64(ready.Sys)-int64(before.Sys))/float64(routes), "agent_sys_B/route")
	b.ReportMetric(float64(ready.Goroutines-before.Goroutines)/float64(routes), "agent_goroutines/route")
	b.ReportMetric(float64(ready.OpenFDs-before.OpenFDs)/float64(routes), "agent_fds/route")
	if before.RSS >= 0 && ready.RSS >= 0 {
		b.ReportMetric(float64(ready.RSS-before.RSS)/float64(routes), "agent_rss_B/route")
	}
	b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)), "agent_residual_heap_B")
	b.ReportMetric(float64(after.Goroutines-before.Goroutines), "agent_residual_goroutines")
	b.ReportMetric(float64(after.OpenFDs-before.OpenFDs), "agent_residual_fds")
}
