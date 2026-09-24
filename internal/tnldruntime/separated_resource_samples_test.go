package tnldruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Keep the resource curve, not just the endpoints of a long held-stream phase.
// In particular, memory.peak is cumulative across phases and cannot establish
// whether memory stopped growing during the measured window.
type separatedResourceSample struct {
	At         time.Time                           `json:"at"`
	Components map[string]separatedSampledResource `json:"components"`
}

type separatedSampledResource struct {
	Memory              uint64 `json:"memory"`
	MemoryAnon          uint64 `json:"memory_anon"`
	Peak                uint64 `json:"cumulative_peak"`
	MemoryMaxEvents     uint64 `json:"memory_max_events"`
	OOMKills            uint64 `json:"oom_kills"`
	CPUUsec             uint64 `json:"cpu_usec"`
	ThrottledUsec       uint64 `json:"throttled_usec"`
	OpenFileDescriptors int    `json:"open_file_descriptors"`
}

type separatedResourceTrend struct {
	Samples               int     `json:"samples"`
	InitialMemory         uint64  `json:"initial_memory"`
	FinalMemory           uint64  `json:"final_memory"`
	MaximumMemory         uint64  `json:"maximum_memory"`
	FirstMinuteMeanMemory uint64  `json:"first_minute_mean_memory"`
	LastMinuteMeanMemory  uint64  `json:"last_minute_mean_memory"`
	MeanCPUCores          float64 `json:"mean_cpu_cores"`
	ThrottledUsec         uint64  `json:"throttled_usec"`
	MemoryMaxEvents       uint64  `json:"memory_max_events"`
	OOMKills              uint64  `json:"oom_kills"`
	MaximumOpenFiles      int     `json:"maximum_open_files"`
}

func summarizeSeparatedResourceSamples(samples []separatedResourceSample) map[string]separatedResourceTrend {
	trends := make(map[string]separatedResourceTrend)
	if len(samples) < 2 {
		return trends
	}
	first, last := samples[0], samples[len(samples)-1]
	for component, initial := range first.Components {
		final := last.Components[component]
		trend := separatedResourceTrend{
			Samples: len(samples), InitialMemory: initial.Memory, FinalMemory: final.Memory,
			ThrottledUsec:   final.ThrottledUsec - initial.ThrottledUsec,
			MemoryMaxEvents: final.MemoryMaxEvents - initial.MemoryMaxEvents,
			OOMKills:        final.OOMKills - initial.OOMKills,
		}
		if seconds := last.At.Sub(first.At).Seconds(); seconds > 0 {
			trend.MeanCPUCores = float64(final.CPUUsec-initial.CPUUsec) / 1e6 / seconds
		}
		var firstSum, lastSum uint64
		var firstCount, lastCount uint64
		for _, sample := range samples {
			value := sample.Components[component]
			trend.MaximumMemory = max(trend.MaximumMemory, value.Memory)
			trend.MaximumOpenFiles = max(trend.MaximumOpenFiles, value.OpenFileDescriptors)
			if sample.At.Before(first.At.Add(time.Minute)) {
				firstSum += value.Memory
				firstCount++
			}
			if !sample.At.Before(last.At.Add(-time.Minute)) {
				lastSum += value.Memory
				lastCount++
			}
		}
		trend.FirstMinuteMeanMemory = firstSum / firstCount
		trend.LastMinuteMeanMemory = lastSum / lastCount
		trends[component] = trend
	}
	return trends
}

func TestSummarizeSeparatedResourceSamples(t *testing.T) {
	start := time.Now()
	var samples []separatedResourceSample
	for index, row := range []struct {
		seconds, memory, cpu, files int
	}{
		{0, 100, 0, 10}, {30, 120, 300_000, 11},
		{90, 130, 900_000, 12}, {240, 140, 2_400_000, 13},
		{270, 130, 2_700_000, 12}, {300, 150, 3_000_000, 11},
	} {
		samples = append(samples, separatedResourceSample{
			At: start.Add(time.Duration(row.seconds) * time.Second),
			Components: map[string]separatedSampledResource{"relay-a": {
				Memory: uint64(row.memory), CPUUsec: uint64(row.cpu), OpenFileDescriptors: row.files,
				MemoryMaxEvents: uint64(index / 5),
			}},
		})
	}
	trend := summarizeSeparatedResourceSamples(samples)["relay-a"]
	if trend.Samples != 6 || trend.InitialMemory != 100 || trend.FinalMemory != 150 || trend.MaximumMemory != 150 ||
		trend.FirstMinuteMeanMemory != 110 || trend.LastMinuteMeanMemory != 140 || trend.MeanCPUCores != 0.01 ||
		trend.MaximumOpenFiles != 13 || trend.MemoryMaxEvents != 1 {
		t.Fatalf("incorrect measured-window trend: %+v", trend)
	}
}

func sampleSeparatedResources(t *testing.T, phase string) func() {
	t.Helper()
	// The runner stops the coordinator when another container exits unexpectedly.
	// Persist samples as they arrive so an OOM still leaves a partial memory curve.
	file, err := os.Create(filepath.Join("/results", phase+"-resource-samples.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan []separatedResourceSample, 1)
	go func() {
		var samples []separatedResourceSample
		defer func() { _ = file.Close(); done <- samples }()
		encoder := json.NewEncoder(file)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		client := &http.Client{Timeout: 2 * time.Second}
		components := []string{"control", "ingress", "relay-a", "relay-b", "publishers", "app", "visitor-1", "visitor-2", "visitor-3", "visitor-4"}
		if *runtimeLoadHATopology {
			components = append(components, "control-b", "ingress-b")
		}
		for {
			sample := separatedResourceSample{At: time.Now(), Components: make(map[string]separatedSampledResource, len(components))}
			for _, component := range components {
				address := separatedInspectionAddress(component) + ":9091"
				if component == "app" {
					address = "publishers:9092"
				}
				response, err := integrationGET(ctx, client, "http://"+address+"/resources")
				if err != nil {
					if ctx.Err() == nil {
						t.Errorf("resource sample %s %s: %v", phase, component, err)
					}
					return
				}
				var resource separatedResources
				err = json.NewDecoder(response.Body).Decode(&resource)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK {
					if ctx.Err() == nil {
						t.Errorf("resource sample %s %s: status=%d error=%v", phase, component, response.StatusCode, err)
					}
					return
				}
				sample.Components[component] = separatedSampledResource{
					Memory: resource.Memory, MemoryAnon: resource.MemoryAnon, Peak: resource.Peak,
					MemoryMaxEvents: resource.MemoryMaxEvents, OOMKills: resource.OOMKills,
					CPUUsec: resource.CPUUsec, ThrottledUsec: resource.ThrottledUsec,
					OpenFileDescriptors: resource.OpenFileDescriptors,
				}
			}
			samples = append(samples, sample)
			if err := encoder.Encode(sample); err != nil {
				t.Errorf("resource sample %s artifact: %v", phase, err)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			samples := <-done
			separatedResult(t, fmt.Sprintf("%s-resource-samples", phase), samples)
			separatedResult(t, fmt.Sprintf("%s-resource-trend", phase), summarizeSeparatedResourceSamples(samples))
		})
	}
	t.Cleanup(stop)
	return stop
}
