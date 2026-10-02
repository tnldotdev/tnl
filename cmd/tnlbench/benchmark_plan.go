package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/clientstate"
)

type benchmarkSuite string

const (
	benchmarkSmoke  benchmarkSuite = "smoke"
	benchmarkTarget benchmarkSuite = "target"
)

type benchmarkMode string

const (
	modeFreshHeld benchmarkMode = "fresh-held"
	modeFresh     benchmarkMode = "fresh"
	modeHeld      benchmarkMode = "held"
	modeBandwidth benchmarkMode = "bandwidth"
	modeCombined  benchmarkMode = "combined"
)

func (m benchmarkMode) fresh() bool {
	return m == modeFreshHeld || m == modeFresh || m == modeCombined
}

func (m benchmarkMode) held() bool {
	return m == modeFreshHeld || m == modeHeld || m == modeCombined
}

func (m benchmarkMode) bandwidth() bool {
	return m == modeBandwidth || m == modeCombined
}

type visitorNetwork string

const (
	visitorTCP  visitorNetwork = "tcp"
	visitorTCP4 visitorNetwork = "tcp4"
	visitorTCP6 visitorNetwork = "tcp6"
)

type workloadOptions struct {
	Suite                       benchmarkSuite                `name:"suite" env:"BENCH_SUITE" default:"smoke" enum:"smoke,target" help:"Small smoke or an explicit target workload."`
	Server                      string                        `name:"server" env:"BENCH_SERVER" required:"" help:"HTTPS control URL of the approved tnl server."`
	Mode                        benchmarkMode                 `name:"mode" env:"BENCH_MODE" default:"fresh-held" enum:"fresh-held,fresh,held,bandwidth,combined" help:"Select the measured visitor workload."`
	Transport                   benchworkload.TransportChoice `name:"transport" env:"BENCH_TRANSPORT" default:"mixed" enum:"mixed,quic,tcp,auto" help:"Forced cohorts or normal QUIC/TLS-TCP selection."`
	QUICDisablePathMTUDiscovery bool                          `name:"quic-disable-path-mtu-discovery" env:"BENCH_QUIC_DISABLE_PATH_MTU_DISCOVERY" help:"Disable publisher QUIC path-MTU discovery for a diagnostic run."`
	QUICQlog                    bool                          `name:"quic-qlog" env:"BENCH_QUIC_QLOG" help:"Record publisher QUIC qlogs in the benchmark result directory."`
	QUICKeepAlive               time.Duration                 `name:"quic-keepalive" env:"BENCH_QUIC_KEEPALIVE" help:"Publisher QUIC keepalive period override for a diagnostic run."`
	VisitorNetwork              visitorNetwork                `name:"visitor-network" env:"BENCH_VISITOR_NETWORK" default:"tcp" enum:"tcp,tcp4,tcp6" help:"Network used by public visitor TCP sockets."`
	VisitorInterface            string                        `name:"visitor-interface" env:"BENCH_VISITOR_INTERFACE" help:"Local interface whose IPv4 address is used by public visitors only."`
	PublicURLs                  int                           `name:"public-urls" env:"BENCH_PUBLIC_URLS" default:"4" help:"Public URLs to publish."`
	StartParallel               int                           `name:"start-parallel" env:"BENCH_START_PARALLEL" default:"4" help:"Publishers activating concurrently."`
	FreshRate                   int                           `name:"fresh-connections-per-second" env:"BENCH_FRESH_CONNECTIONS_PER_SECOND" default:"16" help:"Offered visitor requests per second."`
	HeldStreams                 int                           `name:"held-streams" env:"BENCH_HELD_STREAMS" default:"4" help:"Held visitor streams."`
	BandwidthDirection          string                        `name:"bandwidth-direction" env:"BENCH_BANDWIDTH_DIRECTION" help:"Paced bandwidth direction for bandwidth or combined mode."`
	BandwidthMbits              int64                         `name:"bandwidth-mbits-per-second" env:"BENCH_BANDWIDTH_MBITS_PER_SECOND" help:"Decimal Mbit/s in each selected direction."`
	BandwidthStreams            int                           `name:"bandwidth-streams" env:"BENCH_BANDWIDTH_STREAMS" help:"Concurrent bandwidth streams per direction."`
	Concurrency                 int                           `name:"concurrency" env:"BENCH_CONCURRENCY" default:"128" help:"Concurrent visitor request workers."`
	QueueSlots                  int                           `name:"queue-slots" env:"BENCH_QUEUE_SLOTS" default:"8" help:"Waiting visitor request slots."`
	PayloadBytes                int                           `name:"payload-bytes" env:"BENCH_PAYLOAD_BYTES" default:"32768" help:"Verified response bytes."`
	Repetitions                 int                           `name:"repetitions" env:"BENCH_REPETITIONS" default:"1" help:"Measurement windows."`
	Warmup                      time.Duration                 `name:"warmup" env:"BENCH_WARMUP" default:"5s" help:"Time before measuring."`
	Duration                    time.Duration                 `name:"duration" env:"BENCH_DURATION" default:"10s" help:"Length of each measurement window."`
	StateDir                    string                        `name:"state-dir" env:"BENCH_STATE_DIR" type:"path" help:"Client state with an existing login for the selected server."`
	ResultsRoot                 string                        `name:"results-root" env:"BENCH_RESULTS_ROOT" default:"bench-results" type:"path" help:"Result directory."`
}

type benchmarkPlan struct {
	SchemaVersion int             `json:"schema_version"`
	ReadOnly      bool            `json:"read_only"`
	Server        string          `json:"server"`
	Workload      workloadSummary `json:"workload"`
}

type workloadSummary struct {
	Suite                       benchmarkSuite                `json:"suite"`
	Mode                        benchmarkMode                 `json:"mode"`
	Transport                   benchworkload.TransportChoice `json:"transport"`
	QUICDisablePathMTUDiscovery bool                          `json:"quic_disable_path_mtu_discovery,omitempty"`
	QUICQlog                    bool                          `json:"quic_qlog,omitempty"`
	QUICKeepAlive               time.Duration                 `json:"quic_keepalive,omitempty"`
	VisitorNetwork              visitorNetwork                `json:"visitor_network"`
	VisitorInterface            string                        `json:"visitor_interface,omitempty"`
	PublicURLs                  int                           `json:"public_urls"`
	StartParallel               int                           `json:"start_parallel"`
	FreshRate                   int                           `json:"fresh_connections_per_second"`
	HeldStreams                 int                           `json:"held_streams"`
	BandwidthDirection          string                        `json:"bandwidth_direction,omitempty"`
	BandwidthMbits              int64                         `json:"bandwidth_mbits_per_second_per_direction,omitempty"`
	BandwidthStreams            int                           `json:"bandwidth_streams_per_direction,omitempty"`
	Concurrency                 int                           `json:"concurrency"`
	QueueSlots                  int                           `json:"queue_slots"`
	PayloadBytes                int                           `json:"payload_bytes"`
	Repetitions                 int                           `json:"repetitions"`
	Warmup                      time.Duration                 `json:"warmup"`
	Duration                    time.Duration                 `json:"duration"`
}

func (c workloadOptions) plan() (benchmarkPlan, error) {
	if c.Server == "" {
		return benchmarkPlan{}, errors.New("benchmark requires --server or BENCH_SERVER")
	}
	server, err := clientstate.CanonicalServer(c.Server)
	if err != nil {
		return benchmarkPlan{}, err
	}
	if c.Suite != benchmarkSmoke && c.Suite != benchmarkTarget {
		return benchmarkPlan{}, errors.New("suite must be smoke or target")
	}
	if !c.Transport.Valid() {
		return benchmarkPlan{}, errors.New("transport must be mixed, quic, tcp, or auto")
	}
	if c.Mode != modeFreshHeld && c.Mode != modeFresh && c.Mode != modeHeld && c.Mode != modeBandwidth && c.Mode != modeCombined {
		return benchmarkPlan{}, errors.New("mode must be fresh-held, fresh, held, bandwidth, or combined")
	}
	if c.VisitorNetwork != visitorTCP && c.VisitorNetwork != visitorTCP4 && c.VisitorNetwork != visitorTCP6 {
		return benchmarkPlan{}, errors.New("visitor network must be tcp, tcp4, or tcp6")
	}
	if c.QUICKeepAlive < 0 || c.QUICKeepAlive > 0 && (c.QUICKeepAlive < time.Second || c.QUICKeepAlive > time.Minute) {
		return benchmarkPlan{}, errors.New("QUIC keepalive must be zero or between 1s and 1m")
	}
	if c.VisitorInterface != "" {
		if c.VisitorNetwork == visitorTCP6 {
			return benchmarkPlan{}, errors.New("a selected visitor interface requires IPv4 visitor sockets")
		}
		if _, err := visitorSourceAddress(c.VisitorInterface); err != nil {
			return benchmarkPlan{}, err
		}
	}
	if c.PublicURLs < 1 || c.PublicURLs > 10_000 || c.StartParallel < 1 || c.StartParallel > 1000 || c.FreshRate < 0 || c.FreshRate > 10_000 || c.HeldStreams < 0 || c.HeldStreams > 100_000 || c.Concurrency < 1 || c.Concurrency > 100_000 || c.QueueSlots < 0 || c.QueueSlots > 10_000 || c.PayloadBytes < 1 || c.PayloadBytes > 16<<20 || c.Repetitions < 1 || c.Repetitions > 10 || c.Warmup < 0 || c.Warmup > 5*time.Minute || c.Duration < time.Second || c.Duration > time.Hour {
		return benchmarkPlan{}, errors.New("invalid workload shape or duration")
	}
	if c.Mode.fresh() != (c.FreshRate > 0) || !c.Mode.held() && c.HeldStreams != 0 || (c.Mode == modeHeld || c.Mode == modeCombined) && c.HeldStreams == 0 {
		return benchmarkPlan{}, errors.New("fresh rate and held streams must match the selected mode")
	}
	if c.Mode.bandwidth() {
		if c.BandwidthDirection != benchworkload.BandwidthDownstream && c.BandwidthDirection != benchworkload.BandwidthUpstream && c.BandwidthDirection != benchworkload.BandwidthBidirectional || c.BandwidthStreams < 1 || c.BandwidthStreams > 4096 || c.BandwidthMbits < 1 || c.BandwidthMbits > 10_000 || c.BandwidthMbits*1_000_000/8 < int64(c.BandwidthStreams) || c.BandwidthMbits*1_000_000/8 > int64(c.BandwidthStreams)*(1<<30) {
			return benchmarkPlan{}, errors.New("bandwidth requires a direction, 1-4096 streams, and 1-10000 Mbit/s per direction")
		}
	} else if c.BandwidthDirection != "" || c.BandwidthMbits != 0 || c.BandwidthStreams != 0 {
		return benchmarkPlan{}, errors.New("bandwidth settings require bandwidth or combined mode")
	}
	if c.Suite == benchmarkSmoke && (c.Mode != modeFreshHeld || c.StartParallel != 4 || c.Transport != benchworkload.TransportMixed || c.PublicURLs > 4 || c.FreshRate > 16 ||
		c.HeldStreams > 4 || c.Concurrency > 128 || c.QueueSlots > 8 || c.PayloadBytes > 32<<10 ||
		c.Repetitions != 1 || c.Warmup > 5*time.Second || c.Duration > 30*time.Second) {
		return benchmarkPlan{}, errors.New("larger workloads require suite target")
	}
	return benchmarkPlan{SchemaVersion: 3, ReadOnly: true, Server: server,
		Workload: workloadSummary{Suite: c.Suite, Mode: c.Mode, Transport: c.Transport, QUICDisablePathMTUDiscovery: c.QUICDisablePathMTUDiscovery, QUICQlog: c.QUICQlog, QUICKeepAlive: c.QUICKeepAlive, VisitorNetwork: c.VisitorNetwork, VisitorInterface: c.VisitorInterface, PublicURLs: c.PublicURLs, StartParallel: c.StartParallel, FreshRate: c.FreshRate,
			HeldStreams: c.HeldStreams, BandwidthDirection: c.BandwidthDirection, BandwidthMbits: c.BandwidthMbits, BandwidthStreams: c.BandwidthStreams, Concurrency: c.Concurrency, QueueSlots: c.QueueSlots,
			PayloadBytes: c.PayloadBytes, Repetitions: c.Repetitions, Warmup: c.Warmup, Duration: c.Duration}}, nil
}

type benchmarkPlanFormat string

const (
	benchmarkPlanHuman benchmarkPlanFormat = "human"
	benchmarkPlanJSON  benchmarkPlanFormat = "json"
)

type planCommand struct {
	workloadOptions
	Format benchmarkPlanFormat `name:"format" default:"human" enum:"human,json" help:"Plan output format."`
}

func (c planCommand) run(stdout io.Writer) error {
	plan, err := c.plan()
	if err != nil {
		return err
	}
	if c.Format == benchmarkPlanJSON {
		return json.NewEncoder(stdout).Encode(plan)
	}
	fmt.Fprintf(stdout, "Benchmark plan (READ ONLY)\nServer: %s\nGenerators: local publisher and visitor\n", plan.Server)
	fmt.Fprintf(stdout, "Publisher transport: %s\n", c.Transport)
	if c.QUICDisablePathMTUDiscovery {
		fmt.Fprintln(stdout, "Publisher QUIC path-MTU discovery: disabled")
	}
	if c.QUICQlog {
		fmt.Fprintln(stdout, "Publisher QUIC qlog: enabled")
	}
	if c.QUICKeepAlive > 0 {
		fmt.Fprintf(stdout, "Publisher QUIC keepalive: %s\n", c.QUICKeepAlive)
	}
	fmt.Fprintf(stdout, "Visitor network: %s", c.VisitorNetwork)
	if c.VisitorInterface != "" {
		fmt.Fprintf(stdout, " via %s", c.VisitorInterface)
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "Workload: %s, %d public URLs, %d activating, %d fresh/s, %d held, %d bytes\n", c.Mode, c.PublicURLs, c.StartParallel, c.FreshRate, c.HeldStreams, c.PayloadBytes)
	fmt.Fprintf(stdout, "Visitor workers: %d; waiting slots: %d\n", c.Concurrency, c.QueueSlots)
	if c.Mode.bandwidth() {
		fmt.Fprintf(stdout, "Bandwidth: %s, %d Mbit/s per direction, %d streams per direction\n", c.BandwidthDirection, c.BandwidthMbits, c.BandwidthStreams)
	}
	fmt.Fprintf(stdout, "Windows: %d x %s; warmup per path %s; local direct baseline %s\n", c.Repetitions, c.Duration, c.Warmup, c.Duration)
	_, err = fmt.Fprintln(stdout, "Execution requires an explicit BENCH_SUITE and BENCH_APPROVED=1.")
	return err
}

type runCommand struct {
	workloadOptions
	Approved string `name:"approved" env:"BENCH_APPROVED" help:"Explicit approval for this server and workload; must be 1."`
}

func (c runCommand) validate() (benchmarkPlan, error) {
	plan, err := c.plan()
	if err != nil {
		return plan, err
	}
	if c.Approved != "1" {
		return plan, errors.New("BENCH_APPROVED must be exactly 1; planning does not grant execution approval")
	}
	if value, found := os.LookupEnv("BENCH_SUITE"); !found || value == "" || value != string(c.Suite) {
		return plan, errors.New("execution requires an explicit BENCH_SUITE environment variable")
	}
	return plan, nil
}
