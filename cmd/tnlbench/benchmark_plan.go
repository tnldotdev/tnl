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

type visitorNetwork string

const (
	visitorTCP  visitorNetwork = "tcp"
	visitorTCP4 visitorNetwork = "tcp4"
	visitorTCP6 visitorNetwork = "tcp6"
)

type workloadOptions struct {
	Suite                       benchmarkSuite                `name:"suite" env:"BENCH_SUITE" default:"smoke" enum:"smoke,target" help:"Small smoke or an explicit target workload."`
	Server                      string                        `name:"server" env:"BENCH_SERVER" required:"" help:"HTTPS control URL of the approved tnl server."`
	Transport                   benchworkload.TransportChoice `name:"transport" env:"BENCH_TRANSPORT" default:"mixed" enum:"mixed,quic,tcp,auto" help:"Forced cohorts or normal QUIC/TLS-TCP selection."`
	QUICDisablePathMTUDiscovery bool                          `name:"quic-disable-path-mtu-discovery" env:"BENCH_QUIC_DISABLE_PATH_MTU_DISCOVERY" help:"Disable publisher QUIC path-MTU discovery for a diagnostic run."`
	QUICQlog                    bool                          `name:"quic-qlog" env:"BENCH_QUIC_QLOG" help:"Record publisher QUIC qlogs in the benchmark result directory."`
	QUICKeepAlive               time.Duration                 `name:"quic-keepalive" env:"BENCH_QUIC_KEEPALIVE" help:"Publisher QUIC keepalive period override for a diagnostic run."`
	VisitorNetwork              visitorNetwork                `name:"visitor-network" env:"BENCH_VISITOR_NETWORK" default:"tcp" enum:"tcp,tcp4,tcp6" help:"Network used by public visitor TCP sockets."`
	VisitorInterface            string                        `name:"visitor-interface" env:"BENCH_VISITOR_INTERFACE" help:"Local interface whose IPv4 address is used by public visitors only."`
	PublicURLs                  int                           `name:"public-urls" env:"BENCH_PUBLIC_URLS" default:"4" help:"Public URLs to publish."`
	FreshRate                   int                           `name:"fresh-connections-per-second" env:"BENCH_FRESH_CONNECTIONS_PER_SECOND" default:"16" help:"Offered visitor requests per second."`
	HeldStreams                 int                           `name:"held-streams" env:"BENCH_HELD_STREAMS" default:"4" help:"Held visitor streams."`
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
	Transport                   benchworkload.TransportChoice `json:"transport"`
	QUICDisablePathMTUDiscovery bool                          `json:"quic_disable_path_mtu_discovery,omitempty"`
	QUICQlog                    bool                          `json:"quic_qlog,omitempty"`
	QUICKeepAlive               time.Duration                 `json:"quic_keepalive,omitempty"`
	VisitorNetwork              visitorNetwork                `json:"visitor_network"`
	VisitorInterface            string                        `json:"visitor_interface,omitempty"`
	PublicURLs                  int                           `json:"public_urls"`
	FreshRate                   int                           `json:"fresh_connections_per_second"`
	HeldStreams                 int                           `json:"held_streams"`
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
	if c.PublicURLs < 1 || c.PublicURLs > 10_000 || c.FreshRate < 1 || c.FreshRate > 10_000 || c.HeldStreams < 0 || c.HeldStreams > 100_000 || c.Concurrency < 1 || c.Concurrency > 100_000 || c.QueueSlots < 0 || c.QueueSlots > 10_000 || c.PayloadBytes < 1 || c.PayloadBytes > 16<<20 || c.Repetitions < 1 || c.Repetitions > 10 || c.Warmup < 0 || c.Warmup > 5*time.Minute || c.Duration < time.Second || c.Duration > time.Hour {
		return benchmarkPlan{}, errors.New("invalid workload shape or duration")
	}
	if c.Suite == benchmarkSmoke && (c.Transport != benchworkload.TransportMixed || c.PublicURLs > 4 || c.FreshRate > 16 ||
		c.HeldStreams > 4 || c.Concurrency > 128 || c.QueueSlots > 8 || c.PayloadBytes > 32<<10 ||
		c.Repetitions != 1 || c.Warmup > 5*time.Second || c.Duration > 30*time.Second) {
		return benchmarkPlan{}, errors.New("larger workloads require suite target")
	}
	return benchmarkPlan{SchemaVersion: 2, ReadOnly: true, Server: server,
		Workload: workloadSummary{Suite: c.Suite, Transport: c.Transport, QUICDisablePathMTUDiscovery: c.QUICDisablePathMTUDiscovery, QUICQlog: c.QUICQlog, QUICKeepAlive: c.QUICKeepAlive, VisitorNetwork: c.VisitorNetwork, VisitorInterface: c.VisitorInterface, PublicURLs: c.PublicURLs, FreshRate: c.FreshRate,
			HeldStreams: c.HeldStreams, Concurrency: c.Concurrency, QueueSlots: c.QueueSlots,
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
	fmt.Fprintf(stdout, "Workload: %d public URLs, %d fresh/s, %d held, %d bytes\n", c.PublicURLs, c.FreshRate, c.HeldStreams, c.PayloadBytes)
	fmt.Fprintf(stdout, "Windows: %d x %s; warmup %s; local direct baseline %s\n", c.Repetitions, c.Duration, c.Warmup, c.Duration)
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
