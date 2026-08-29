package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/0xcadams/tnl/internal/tailbench"
	"github.com/0xcadams/tnl/internal/tailtransport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const maxRoutes = 1000

func main() {
	listen := flag.String("listen", "[::]:8080", "private control listen address")
	regionID := flag.Int("region", 302, "public Tailcat DERP region")
	flag.Parse()
	if flag.NArg() != 1 || flag.Arg(0) != "agent" {
		log.Fatal("usage: tailbench [flags] agent")
	}
	token := os.Getenv("TNL_TAILBENCH_TOKEN")
	if token == "" {
		log.Fatal("TNL_TAILBENCH_TOKEN is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	region, err := tailbench.PublicRegion(ctx, *regionID)
	if err != nil {
		log.Fatal(err)
	}
	agent := &agent{token: token, region: region}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.Handle("/v1/run", agent.authorize(http.HandlerFunc(agent.handleRun)))
	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		agent.closeRun(shutdownCtx)
	}()
	log.Printf("tailbench agent ready on %s using public DERP region %d", *listen, *regionID)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

type agent struct {
	mu      sync.Mutex
	token   string
	region  *tailcfg.DERPRegion
	servers []*tailtransport.Server
	before  tailbench.Resources
}

func (a *agent) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(a.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *agent) handleRun(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		a.createRun(w, r)
	case http.MethodDelete:
		a.deleteRun(w, r)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *agent) createRun(w http.ResponseWriter, r *http.Request) {
	var request tailbench.CreateRunRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if len(request.ClientPublicKeys) == 0 || len(request.ClientPublicKeys) > maxRoutes {
		http.Error(w, "route count must be between 1 and 1000", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.servers) != 0 {
		http.Error(w, "run already active", http.StatusConflict)
		return
	}
	a.before = readResources()
	servers := make([]*tailtransport.Server, len(request.ClientPublicKeys))
	endpoints := make([]tailbench.Endpoint, len(request.ClientPublicKeys))
	err := parallel(len(servers), 8, func(index int) error {
		var clientKey key.NodePublic
		if err := clientKey.UnmarshalText([]byte(request.ClientPublicKeys[index])); err != nil || clientKey.IsZero() {
			return errors.New("invalid client public key")
		}
		server, err := tailtransport.NewServer(tailtransport.ServerConfig{
			AllowedClient: clientKey,
			RelayProfile:  tailbench.RelayProfile,
			Profiles:      map[string]*tailcfg.DERPRegion{tailbench.RelayProfile: a.region},
			Handler: func(conn net.Conn) {
				_, _ = io.Copy(conn, conn)
			},
			Logf: logger.Discard,
		})
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		endpoint, err := server.Start(ctx)
		if err != nil {
			server.Close()
			return err
		}
		servers[index] = server
		endpoints[index] = tailbench.Endpoint{
			Version:         endpoint.Version,
			ServerPublicKey: endpoint.ServerPublicKey,
			RelayProfile:    endpoint.RelayProfile,
		}
		return nil
	})
	if err != nil {
		closeServers(context.Background(), servers)
		http.Error(w, fmt.Sprintf("start routes: %v", err), http.StatusInternalServerError)
		return
	}
	a.servers = servers
	writeJSON(w, tailbench.CreateRunResponse{Endpoints: endpoints, Before: a.before, Ready: readResources()})
}

func (a *agent) deleteRun(w http.ResponseWriter, r *http.Request) {
	if err := a.closeRun(r.Context()); err != nil {
		http.Error(w, fmt.Sprintf("close routes: %v", err), http.StatusInternalServerError)
		return
	}
	runtime.GC()
	runtime.GC()
	writeJSON(w, tailbench.CloseRunResponse{After: readResources()})
}

func (a *agent) closeRun(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	servers := a.servers
	a.servers = nil
	return closeServers(ctx, servers)
}

func closeServers(ctx context.Context, servers []*tailtransport.Server) error {
	return parallel(len(servers), 8, func(index int) error {
		server := servers[index]
		if server == nil {
			return nil
		}
		drainCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		drainErr := server.Drain(drainCtx)
		closeErr := server.Close()
		servers[index] = nil
		return errors.Join(drainErr, closeErr)
	})
}

func parallel(count, limit int, run func(int) error) error {
	if count == 0 {
		return nil
	}
	jobs := make(chan int)
	errs := make(chan error, count)
	var workers sync.WaitGroup
	for range min(count, limit) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if err := run(index); err != nil {
					errs <- fmt.Errorf("route %d: %w", index, err)
				}
			}
		}()
	}
	for index := range count {
		jobs <- index
	}
	close(jobs)
	workers.Wait()
	close(errs)
	var failures []error
	for err := range errs {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func readResources() tailbench.Resources {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return tailbench.Resources{
		HeapAlloc:  memory.HeapAlloc,
		Sys:        memory.Sys,
		RSS:        currentRSS(),
		Goroutines: runtime.NumGoroutine(),
		OpenFDs:    openFDs(),
	}
}

func currentRSS() int64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return -1
	}
	var totalPages, residentPages int64
	if _, err := fmt.Sscan(string(data), &totalPages, &residentPages); err != nil {
		return -1
	}
	return residentPages * int64(os.Getpagesize())
}

func openFDs() int {
	for _, path := range []string{"/proc/self/fd", "/dev/fd"} {
		if entries, err := os.ReadDir(path); err == nil {
			return len(entries)
		}
	}
	return -1
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write response: %v", err)
	}
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if value := os.Getenv("GOMAXPROCS"); value != "" {
		if _, err := strconv.Atoi(value); err != nil {
			log.Printf("invalid GOMAXPROCS %q", value)
		}
	}
}
