package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/clientstate"
)

type reportCommand struct {
	RunDirectory string `name:"run" env:"BENCH_RUN" type:"path" required:"" help:"Directory from an earlier run."`
}

func (c reportCommand) run(stdout io.Writer) error {
	data, err := os.ReadFile(filepath.Join(c.RunDirectory, "result.json"))
	if err != nil {
		return err
	}
	var result benchmarkResult
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	server, err := clientstate.CanonicalServer(result.Plan.Server)
	if result.SchemaVersion != 1 && result.SchemaVersion != 2 && result.SchemaVersion != 3 || err != nil || server != result.Plan.Server {
		return errors.New("invalid benchmark result")
	}
	return printResult(stdout, result)
}

func printResult(stdout io.Writer, result benchmarkResult) error {
	cleanup := result.CleanupStatus
	if cleanup == "" {
		cleanup = "unknown"
		if result.CleanupExact {
			cleanup = "succeeded"
		}
	}
	if _, err := fmt.Fprintf(stdout, "%s: %s (%d public URLs; cleanup: %s)\n", result.RunID, result.Status, len(result.PublicURLs), cleanup); err != nil {
		return err
	}
	if result.Activation > 0 {
		if _, err := fmt.Fprintf(stdout, "activation: %d public URLs in %s\n", len(result.PublicURLs), result.Activation); err != nil {
			return err
		}
	}
	if result.Plan.Workload.Mode == "" || result.Plan.Workload.Mode.fresh() {
		if _, err := fmt.Fprintf(stdout, "direct: %d/%d successful; p95 %s\n", result.Direct.Successes, result.Direct.Scheduled, p95(&result.Direct)); err != nil {
			return err
		}
	}
	if result.DirectWarmupBandwidth != nil && len(result.DirectWarmupBandwidth.FailureSamples) != 0 {
		if err := printBandwidth(stdout, "direct warmup", *result.DirectWarmupBandwidth); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stdout, "  first warmup failure: %s\n", result.DirectWarmupBandwidth.FailureSamples[0]); err != nil {
			return err
		}
	}
	if result.DirectHeld != nil {
		if _, err := fmt.Fprintf(stdout, "direct held: %d/%d progressing; %d bytes\n", result.DirectHeld.Progressing, result.DirectHeld.Open, result.DirectHeld.Bytes); err != nil {
			return err
		}
	}
	if result.DirectBandwidth != nil {
		if err := printBandwidth(stdout, "direct bandwidth", *result.DirectBandwidth); err != nil {
			return err
		}
	}
	if result.WarmupBandwidth != nil {
		if err := printBandwidth(stdout, "server warmup", *result.WarmupBandwidth); err != nil {
			return err
		}
		if err := printBandwidthPublicURLs(stdout, *result.WarmupBandwidth, result.PublicURLInfo); err != nil {
			return err
		}
		if len(result.WarmupBandwidth.FailureSamples) != 0 {
			if _, err := fmt.Fprintf(stdout, "  first warmup failure: %s\n", result.WarmupBandwidth.FailureSamples[0]); err != nil {
				return err
			}
		}
	}
	for index, phase := range result.Steady {
		if _, err := fmt.Fprintf(stdout, "server %d: %d/%d successful; p95 %s\n", index+1, phase.Successes, phase.Scheduled, p95(&phase)); err != nil {
			return err
		}
		if index < len(result.SteadyByURL) {
			for _, publicURL := range result.PublicURLInfo {
				summary := result.SteadyByURL[index][publicURL.PublicURL]
				if summary == nil {
					continue
				}
				if _, err := fmt.Fprintf(stdout, "  %s %s %s: %d/%d successful; %d missed; %d timed out\n",
					publicURL.PublicURL, publicURL.PublicURLID, publicURL.Transport,
					summary.Successes, summary.Scheduled, summary.Missed, summary.Timeouts); err != nil {
					return err
				}
			}
		}
	}
	for index, held := range result.SteadyHeld {
		if _, err := fmt.Fprintf(stdout, "server held %d: %d/%d progressing; %d bytes\n", index+1, held.Progressing, held.Open, held.Bytes); err != nil {
			return err
		}
	}
	for index, bandwidth := range result.SteadyBandwidth {
		if err := printBandwidth(stdout, fmt.Sprintf("server bandwidth %d", index+1), bandwidth); err != nil {
			return err
		}
		if err := printBandwidthPublicURLs(stdout, bandwidth, result.PublicURLInfo); err != nil {
			return err
		}
	}
	if result.Plan.Workload.Transport == "auto" {
		if _, err := fmt.Fprintf(stdout, "auto: %d TLS/TCP selection events\n", len(result.Fallbacks)); err != nil {
			return err
		}
	}
	if result.Generator.Elapsed > 0 {
		if _, err := fmt.Fprintf(stdout, "generator: %d goroutines; %d heap bytes; elapsed %s\n", result.Generator.Goroutines, result.Generator.HeapBytes, result.Generator.Elapsed); err != nil {
			return err
		}
	}
	if result.Error != "" {
		_, err := fmt.Fprintf(stdout, "failure: %s\n", result.Error)
		return err
	}
	return nil
}

func printBandwidth(stdout io.Writer, name string, result benchworkload.BandwidthResult) error {
	_, err := fmt.Fprintf(stdout, "%s: %s, %d streams/direction, target %.1f Mbit/s/direction; upload %d/%d bytes (%.1f Mbit/s), download %d/%d bytes (%.1f Mbit/s); %d failures; elapsed %s\n",
		name, result.Direction, result.StreamsPerDirection, float64(result.TargetBytesPerSecond)*8/1_000_000,
		result.UploadBytes, result.ExpectedUploadBytes, result.UploadBytesPerSecond*8/1_000_000,
		result.DownloadBytes, result.ExpectedDownloadBytes, result.DownloadBytesPerSecond*8/1_000_000, result.Failures, result.Elapsed)
	if err != nil || result.SetupDuration == 0 {
		return err
	}
	_, err = fmt.Fprintf(stdout, "  bandwidth connections prepared in %s before measurement\n", result.SetupDuration)
	if err != nil {
		return err
	}
	var afterWindow int64
	for _, second := range result.PerSecond {
		if time.Duration(second.Second)*time.Second >= result.TargetDuration {
			afterWindow += second.UploadBytes + second.DownloadBytes
		}
	}
	if afterWindow > 0 {
		_, err = fmt.Fprintf(stdout, "  %d verified bytes arrived after the requested window\n", afterWindow)
	}
	return err
}

func printBandwidthPublicURLs(stdout io.Writer, result benchworkload.BandwidthResult, urls []benchmarkPublicURL) error {
	for _, publicURL := range urls {
		var streams, failures int
		var expected, transferred int64
		var first, last time.Duration
		for _, stream := range result.Streams {
			if stream.URL != publicURL.PublicURL {
				continue
			}
			streams++
			expected += stream.ExpectedBytes
			transferred += stream.Bytes
			first = max(first, stream.FirstByteDelay)
			last = max(last, stream.LastByteDelay)
			if stream.Error != "" {
				failures++
			}
		}
		if streams > 0 {
			if _, err := fmt.Fprintf(stdout, "  %s %s: %d streams, %d/%d bytes; latest first byte %s; last byte %s; %d failures\n",
				publicURL.PublicURL, publicURL.Transport, streams, transferred, expected, first, last, failures); err != nil {
				return err
			}
		}
	}
	return nil
}

func p95(result *benchworkload.VisitorResult) string {
	value := result.Total.Percentile(95)
	if value == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f ms", *value)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".result-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
