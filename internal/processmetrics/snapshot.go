package processmetrics

import (
	"os"
	"runtime"
	"runtime/metrics"
)

type Snapshot struct {
	HeapAlloc  int64   `json:"heap_alloc"`
	Sys        int64   `json:"sys"`
	RSS        int64   `json:"rss"`
	Goroutines int64   `json:"goroutines"`
	OpenFDs    int64   `json:"open_fds"`
	UserCPU    float64 `json:"user_cpu_seconds"`
}

func Read() Snapshot {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return Snapshot{
		HeapAlloc:  int64(memory.HeapAlloc),
		Sys:        int64(memory.Sys),
		RSS:        currentRSS(),
		Goroutines: int64(runtime.NumGoroutine()),
		OpenFDs:    openFDs(),
		UserCPU:    runtimeMetric("/cpu/classes/user:cpu-seconds"),
	}
}

func openFDs() int64 {
	for _, path := range []string{"/proc/self/fd", "/dev/fd"} {
		if entries, err := os.ReadDir(path); err == nil {
			return int64(len(entries))
		}
	}
	return -1
}

func runtimeMetric(name string) float64 {
	sample := []metrics.Sample{{Name: name}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindFloat64 {
		return 0
	}
	return sample[0].Value.Float64()
}
