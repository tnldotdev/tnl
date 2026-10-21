package observability

// RuntimeInstrumentDefinitions names the supported subset of the pinned
// Prometheus Go/process bridge, using actual OTLP names and data types. summary
// is an OTLP summary, not an explicit-bucket histogram. process metrics can be
// absent on platforms where their collector is unavailable. no prefix wildcard
// admits newly introduced runtime metrics into the hosted contract.
func RuntimeInstrumentDefinitions() []InstrumentDefinition {
	return []InstrumentDefinition{
		{Name: "go_goroutines", Kind: KindGauge, Semantics: "current goroutine count", Dimensions: []Key{}},
		{Name: "go_gc_duration_seconds", Kind: KindSummary, Semantics: "garbage collection pause duration summary from the Go collector", Dimensions: []Key{}},
		{Name: "go_memstats_heap_alloc_bytes", Kind: KindGauge, Semantics: "currently allocated heap bytes", Dimensions: []Key{}},
		{Name: "go_memstats_heap_inuse_bytes", Kind: KindGauge, Semantics: "heap spans in use in bytes", Dimensions: []Key{}},
		{Name: "go_memstats_sys_bytes", Kind: KindGauge, Semantics: "bytes obtained from the operating system", Dimensions: []Key{}},
		{Name: "process_cpu_seconds_total", Kind: KindCounter, Semantics: "cumulative process CPU seconds", Dimensions: []Key{}},
		{Name: "process_resident_memory_bytes", Kind: KindGauge, Semantics: "resident process memory bytes", Dimensions: []Key{}},
		{Name: "process_virtual_memory_bytes", Kind: KindGauge, Semantics: "virtual process memory bytes", Dimensions: []Key{}},
		{Name: "process_start_time_seconds", Kind: KindGauge, Semantics: "process start Unix timestamp in seconds", Dimensions: []Key{}},
		{Name: "process_open_fds", Kind: KindGauge, Semantics: "current open file descriptors when supported", Dimensions: []Key{}},
		{Name: "process_max_fds", Kind: KindGauge, Semantics: "maximum file descriptors when supported", Dimensions: []Key{}},
	}
}
