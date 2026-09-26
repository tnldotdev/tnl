package tnldruntime

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

const separatedDirectory = "/load"
const separatedDomain = "split.integration.test"

var separatedComponent = flag.String("tnl-separated-component", "", "separated runtime load component")

var separatedComponents = []string{"control-a", "ingress-a", "relay-a", "relay-b", "publishers", "publishers-2", "publishers-3", "publishers-4", "visitor-1", "visitor-2", "visitor-3", "visitor-4", "app", "app-2", "app-3", "app-4", "pebble"}

func separatedPublisherComponents() []string {
	return []string{"publishers", "publishers-2", "publishers-3", "publishers-4"}
}

func separatedAppComponents() []string {
	return []string{"app", "app-2", "app-3", "app-4"}
}

func separatedAppPublisher(component string) string {
	return "publishers" + strings.TrimPrefix(component, "app")
}

func separatedPublisherShardKey(index int, event string) string {
	return fmt.Sprintf("publishers-%d.%s", index+1, event)
}

func separatedIngresses() []string {
	if *runtimeLoadHATopology {
		return []string{"ingress-a", "ingress-b"}
	}
	return []string{"ingress-a"}
}

func separatedControls() []string {
	if *runtimeLoadHATopology {
		return []string{"control-a", "control-b"}
	}
	return []string{"control-a"}
}

func separatedServerRoles() []string {
	roles := append(append(separatedControls(), separatedIngresses()...), "relay-a", "relay-b")
	if *runtimeLoadScenario == "control-restart" {
		roles = append(roles, "relay-a-2", "relay-b-2")
	}
	return roles
}

func separatedActiveComponents() []string {
	components := slices.Clone(separatedComponents)
	if *runtimeLoadHATopology {
		components = append(components, "control-b", "ingress-b")
	}
	if *runtimeLoadScenario == "control-restart" {
		components = append(components, "relay-a-2", "relay-b-2")
	}
	return components
}

func separatedCAOrders(t *testing.T) int64 {
	t.Helper()
	var orders int64
	for _, name := range separatedControls() {
		orders += separatedResource(t, name).CAOrders
	}
	return orders
}

func separatedCoordination(t *testing.T) *benchworkload.Coordination {
	t.Helper()
	data, err := os.ReadFile("/load/coordinator-token")
	if err != nil {
		t.Fatal(err)
	}
	client, err := benchworkload.NewCoordination("http://coordinator:8080", string(data))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// Coordination uses the same authenticated HTTP events as Fly. The shared
// volume contains only fixture keys/configuration, never lifecycle barriers.
func separatedWrite(t *testing.T, name string, value any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if err := separatedCoordination(t).Put(ctx, name, value); err != nil {
		t.Fatal(err)
	}
}

func separatedArtifact(t *testing.T, name string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(separatedDirectory, name+".json")
	if err := os.WriteFile(path+".tmp", data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

func separatedRead(t *testing.T, ctx context.Context, name string, value any) bool {
	t.Helper()
	if err := separatedCoordination(t).Wait(ctx, name, value); err != nil {
		if ctx.Err() != nil {
			return false
		}
		t.Fatal(err)
	}
	return true
}

func separatedWait(t *testing.T, name string, timeout time.Duration, value any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	if !separatedRead(t, ctx, name, value) {
		t.Fatalf("separated component deadline waiting for %s", name)
	}
}

func separatedRoots(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(separatedDirectory, path))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		t.Fatal("invalid test roots")
	}
	return roots
}

func separatedHTTP(t *testing.T) *http.Client {
	client, _ := newIntegrationHTTPSClient(t, separatedRoots(t, "roots.pem"), "", false)
	return client
}

func TestSeparatedRuntimeSetup(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierRuntimeLoad)
	if *separatedComponent != "setup" {
		t.Skip("run task go:test:load:runtime")
	}
	if err := controlstate.Migrate(t.Context(), testutil.PostgresURL(t)); err != nil {
		t.Fatal(err)
	}
	ca := newIntegrationTestCA(t)
	if err := os.WriteFile("/load/coordinator-token", []byte(rand.Text()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(separatedDirectory, "roots.pem"), ca.certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"control", "relay-a", "relay-b", "pebble", "direct"} {
		hostname := role + "." + separatedDomain
		if role == "pebble" {
			hostname = "pebble"
		}
		material := ca.issue(t, hostname)
		if err := errors.Join(os.WriteFile(filepath.Join(separatedDirectory, role+".pem"), material.certificatePEM, 0o600),
			os.WriteFile(filepath.Join(separatedDirectory, role+".key"), material.privateKeyPEM, 0o600)); err != nil {
			t.Fatal(err)
		}
	}
	separatedArtifact(t, "pebble-config", map[string]any{"pebble": map[string]any{
		"listenAddress": "0.0.0.0:14000", "managementListenAddress": "0.0.0.0:15000",
		"certificate": "/load/pebble.pem", "privateKey": "/load/pebble.key",
		"httpPort": 80, "tlsPort": 443, "externalAccountBindingRequired": false,
		"retryAfter": map[string]int{"authz": 0, "order": 0}, "keyAlgorithm": "ecdsa",
		"profiles": map[string]any{"default": map[string]any{"description": "integration", "validityPeriod": 3600},
			"tlsserver": map[string]any{"description": "tnl route TLS", "validityPeriod": 3600}},
	}})
}

func separatedConfig(t *testing.T, component string) tnldconfig.Config {
	t.Helper()
	role := tnldconfig.Role(component)
	if component == "control-a" || component == "control-b" {
		role = tnldconfig.RoleControl
	}
	if component == "ingress-a" || component == "ingress-b" {
		role = tnldconfig.RoleIngress
	}
	if strings.HasPrefix(component, "relay-") {
		role = tnldconfig.RoleRelay
	}
	cfg := splitTestConfig(role, "0.0.0.0:9090")
	cfg.IngressLeaseDuration, cfg.RelayLeaseDuration = 30*time.Second, 30*time.Second
	cfg.LeaseRenewalInterval, cfg.DrainTimeout = 10*time.Second, 5*time.Second
	if role == tnldconfig.RoleIngress && *runtimeLoadCapacityOnly {
		cfg.DrainTimeout = 30 * time.Second
	}
	runtimeLoadAdmission.apply(&cfg)
	cfg.RouteCertificateWorkers = *runtimeLoadCertificateWorkers
	cfg.QUICIdleTimeout = 45 * time.Second
	cfg.ClusterSecret = testClusterSecret
	switch role {
	case tnldconfig.RoleControl:
		cfg.DatabaseURL = testutil.PostgresURL(t)
		cfg.ControlListen, cfg.PrivateControlListen = "0.0.0.0:443", "0.0.0.0:9443"
		cfg.ServerDomain, cfg.ManagedDeploymentDomain = separatedDomain, "routes."+separatedDomain
		cfg.ControlTLSCertificateFile, cfg.ControlTLSPrivateKeyFile = "/load/control.pem", "/load/control.key"
		cfg.ACMEDirectoryURL, cfg.ACMEEmail = "https://pebble:14000/dir", "integration@example.test"
		cfg.ACMEAcceptTerms, cfg.ACMEProfile = true, "tlsserver"
		cfg.LoginToken, cfg.StorageKey = testLoginToken, testStorageKey
		cfg.AccessTokenLifetime, cfg.RefreshTokenLifetime = 5*time.Minute, time.Hour
	case tnldconfig.RoleIngress:
		cfg.ControlHostname, cfg.IngressID = "control."+separatedDomain, component+"-separated"
		cfg.IngressListen = "0.0.0.0:443"
	case tnldconfig.RoleRelay:
		cfg.ControlHostname = "control." + separatedDomain
		serviceID := strings.TrimSuffix(component, "-2")
		cfg.RelayServiceID, cfg.RelayID = serviceID, serviceID+"-1"
		if serviceID != component {
			cfg.RelayID = serviceID + "-2"
		}
		cfg.RelayAddress = serviceID + "." + separatedDomain + ":443"
		cfg.RelayTLSCertificateFile, cfg.RelayTLSPrivateKeyFile = "/load/"+serviceID+".pem", "/load/"+serviceID+".key"
		cfg.RelayTCPListen, cfg.RelayUDPListen = "0.0.0.0:443", "0.0.0.0:443"
		cfg.InternalRelayListen, cfg.InternalRelayAddress = "0.0.0.0:8443", component+":8443"
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

type separatedResources struct {
	ProcessRunID                                       string
	NetworkNamespace                                   string
	At                                                 time.Time
	CPUQuota, MemoryLimit                              string
	CPUUsec, ThrottledUsec                             uint64
	Periods, ThrottledPeriods                          uint64
	Memory, Peak                                       uint64
	MemoryAnon, MemoryFile, MemoryKernel               uint64
	MemoryKernelStack, MemoryPageTables, MemorySock    uint64
	MemorySlab, MemoryShmem                            uint64
	MemoryFileDirty, MemoryFileWriteback               uint64
	MemoryLowEvents, MemoryHighEvents, MemoryMaxEvents uint64
	OOMEvents, OOMKills, OOMGroupKills                 uint64
	ReceiveBytes, SendBytes                            uint64
	GOMAXPROCS                                         int
	OpenFileDescriptors                                int
	CAOrders                                           int64
	Postgres                                           *separatedPostgresResources `json:",omitempty"`
}

type separatedPostgresResources struct {
	SharedMemoryBytes  int64
	SharedBuffersBytes int64
	Backends           int64
	BlocksRead         int64
	BlocksHit          int64
	TempBytes          int64
}

func readSeparatedResources() (separatedResources, error) {
	r, err := readSeparatedResourceFiles(func(path string) (string, error) {
		data, err := os.ReadFile(path)
		return strings.TrimSpace(string(data)), err
	})
	r.GOMAXPROCS = runtime.GOMAXPROCS(0)
	r.ProcessRunID = separatedObserverRunID
	if err == nil {
		var files []os.DirEntry
		files, err = os.ReadDir("/proc/self/fd")
		r.OpenFileDescriptors = len(files)
	}
	return r, err
}

var separatedObserverRunID = rand.Text()

func readSeparatedResourceFiles(read func(string) (string, error)) (separatedResources, error) {
	r := separatedResources{At: time.Now()}
	var err error
	if r.CPUQuota, err = read("/sys/fs/cgroup/cpu.max"); err != nil {
		return r, err
	}
	if r.MemoryLimit, err = read("/sys/fs/cgroup/memory.max"); err != nil {
		return r, err
	}
	for file, values := range map[string]map[string]*uint64{
		"cpu.stat": {"usage_usec": &r.CPUUsec, "throttled_usec": &r.ThrottledUsec, "nr_periods": &r.Periods, "nr_throttled": &r.ThrottledPeriods},
		"memory.events": {
			"low": &r.MemoryLowEvents, "high": &r.MemoryHighEvents, "max": &r.MemoryMaxEvents,
			"oom": &r.OOMEvents, "oom_kill": &r.OOMKills, "oom_group_kill": &r.OOMGroupKills,
		},
		"memory.stat": {
			"anon": &r.MemoryAnon, "file": &r.MemoryFile, "kernel": &r.MemoryKernel,
			"kernel_stack": &r.MemoryKernelStack, "pagetables": &r.MemoryPageTables,
			"sock": &r.MemorySock, "slab": &r.MemorySlab, "shmem": &r.MemoryShmem,
			"file_dirty": &r.MemoryFileDirty, "file_writeback": &r.MemoryFileWriteback,
		},
	} {
		text, err := read("/sys/fs/cgroup/" + file)
		if err != nil {
			return r, err
		}
		fields := strings.Fields(text)
		for i := 0; i+1 < len(fields); i += 2 {
			if value := values[fields[i]]; value != nil {
				*value, err = strconv.ParseUint(fields[i+1], 10, 64)
				if err != nil {
					return r, err
				}
			}
		}
	}
	for file, value := range map[string]*uint64{"memory.current": &r.Memory, "memory.peak": &r.Peak} {
		text, err := read("/sys/fs/cgroup/" + file)
		if err != nil {
			return r, err
		}
		*value, err = strconv.ParseUint(text, 10, 64)
		if err != nil {
			return r, err
		}
	}
	text, err := read("/proc/net/dev")
	if err != nil {
		return r, err
	}
	for _, line := range strings.Split(text, "\n") {
		name, counters, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "lo" {
			continue
		}
		fields := strings.Fields(counters)
		if len(fields) != 16 {
			return r, fmt.Errorf("invalid network counters")
		}
		rx, rxErr := strconv.ParseUint(fields[0], 10, 64)
		tx, txErr := strconv.ParseUint(fields[8], 10, 64)
		if err := errors.Join(rxErr, txErr); err != nil {
			return r, err
		}
		r.ReceiveBytes += rx
		r.SendBytes += tx
	}
	return r, nil
}

func serveSeparatedResources(t *testing.T, orders func() int64) {
	t.Helper()
	component := *separatedComponent
	address := ":9091"
	if slices.Contains(separatedAppComponents(), component) {
		address = ":9092"
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/heap" && *runtimeLoadHeapProfile {
			// Profiling forces GC only in explicitly selected diagnostic runs.
			runtime.GC()
			w.Header().Set("Content-Type", "application/octet-stream")
			if err := pprof.WriteHeapProfile(w); err != nil {
				t.Error(err)
			}
			return
		}
		if r.URL.Path != "/resources" {
			http.NotFound(w, r)
			return
		}
		value, err := readSeparatedResources()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		value.CAOrders = orders()
		value.NetworkNamespace = component
		if slices.Contains(separatedAppComponents(), component) {
			value.NetworkNamespace = separatedAppPublisher(component)
		}
		_ = json.NewEncoder(w).Encode(value)
	})}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); <-done })
}

func separatedRelayTLS(t *testing.T) *tls.Config {
	return &tls.Config{RootCAs: separatedRoots(t, "roots.pem"), MinVersion: tls.VersionTLS13}
}
