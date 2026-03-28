package tailbench

import (
	"time"

	"github.com/0xcadams/tnl/internal/processmetrics"
)

type ClientRunResult struct {
	RouteCount         int                     `json:"route_count"`
	TransferBytes      int64                   `json:"transfer_bytes"`
	TransferDurationMS int64                   `json:"transfer_duration_ms"`
	ThroughputMiB      float64                 `json:"throughput_mib_per_second"`
	StartupP95MS       int64                   `json:"startup_p95_ms"`
	FirstByteP95MS     int64                   `json:"first_byte_p95_ms"`
	ShutdownP95MS      int64                   `json:"shutdown_p95_ms"`
	WorkerMetricsOK    bool                    `json:"worker_metrics_ok"`
	WorkerMemoryLimit  int64                   `json:"worker_memory_limit"`
	ClientBefore       processmetrics.Snapshot `json:"client_before"`
	ClientReady        processmetrics.Snapshot `json:"client_ready"`
	ClientAfter        processmetrics.Snapshot `json:"client_after"`
	WorkerBefore       processmetrics.Snapshot `json:"worker_before"`
	WorkerReady        processmetrics.Snapshot `json:"worker_ready"`
	WorkerAfter        processmetrics.Snapshot `json:"worker_after"`
	WorkerForcedCloses int                     `json:"worker_forced_closes"`
	WorkerDrainError   string                  `json:"worker_drain_error,omitempty"`
	StartedAt          time.Time               `json:"started_at"`
	FinishedAt         time.Time               `json:"finished_at"`
}
