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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/0xcadams/tnl/internal/processmetrics"
	"github.com/0xcadams/tnl/internal/tailbench"
	"github.com/0xcadams/tnl/internal/tailtransport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	maxRoutes          = 2000
	cleanupTimeout     = 30 * time.Second
	serverDrainTimeout = 5 * time.Second
)

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
	log.Printf("tailbench agent ready on %s using public DERP region %d", *listen, *regionID)
	if err := serveAgent(ctx, server, agent); err != nil {
		log.Fatal(err)
	}
}

func serveAgent(ctx context.Context, server *http.Server, agent *agent) error {
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()

	serverStopped := false
	var listenerErr error
	select {
	case listenerErr = <-serveErr:
		serverStopped = true
	case <-ctx.Done():
	}

	cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	result := agent.shutdown(cleanupCtx)
	shutdownErr := server.Shutdown(cleanupCtx)
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, server.Close())
	}
	if !serverStopped {
		listenerErr = <-serveErr
	}
	if errors.Is(listenerErr, http.ErrServerClosed) {
		listenerErr = nil
	}
	if result.drainErr != nil {
		log.Printf("forced close after drain: %v", result.drainErr)
	}
	return errors.Join(listenerErr, shutdownErr, result.closeErr)
}

type runState uint8

const (
	runIdle runState = iota
	runCreating
	runActive
	runClosing
)

type agent struct {
	mu         sync.Mutex
	token      string
	region     *tailcfg.DERPRegion
	stopping   bool
	state      runState
	cancel     context.CancelFunc
	completion *runCompletion
	servers    []*tailtransport.Server
}

type closeResult struct {
	forced   int
	drainErr error
	closeErr error
}

type runCompletion struct {
	done   chan struct{}
	result closeResult
}

var (
	errAgentStopping    = errors.New("agent is shutting down")
	errRunAlreadyActive = errors.New("run already active")
)

func (a *agent) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, provided, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || scheme != "Bearer" || subtle.ConstantTimeCompare([]byte(provided), []byte(a.token)) != 1 {
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
		http.Error(w, fmt.Sprintf("route count must be between 1 and %d", maxRoutes), http.StatusBadRequest)
		return
	}
	clientKeys := make([]key.NodePublic, len(request.ClientPublicKeys))
	for index, encoded := range request.ClientPublicKeys {
		if err := clientKeys[index].UnmarshalText([]byte(encoded)); err != nil || clientKeys[index].IsZero() {
			http.Error(w, "invalid client public key", http.StatusBadRequest)
			return
		}
	}

	createCtx, completion, err := a.beginCreate(r.Context())
	if errors.Is(err, errAgentStopping) {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	before := processmetrics.Read()
	servers := make([]*tailtransport.Server, len(request.ClientPublicKeys))
	endpoints := make([]tailtransport.Endpoint, len(request.ClientPublicKeys))
	profiles := map[string]*tailcfg.DERPRegion{tailbench.RelayProfile: a.region}
	err = parallel(len(servers), 8, func(index int) error {
		server, err := tailtransport.NewServer(tailtransport.ServerConfig{
			AllowedClient: clientKeys[index],
			RelayProfile:  tailbench.RelayProfile,
			Profiles:      profiles,
			Handler: func(conn net.Conn) {
				_, _ = io.Copy(conn, conn)
			},
			Logf: logger.Discard,
		})
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(createCtx, 30*time.Second)
		defer cancel()
		endpoint, err := server.Start(ctx)
		if err != nil {
			server.Close()
			return err
		}
		servers[index] = server
		endpoints[index] = endpoint
		return nil
	})
	if err == nil {
		err = createCtx.Err()
	}

	if err == nil && a.activateRun(completion, servers) {
		writeJSON(w, tailbench.CreateRunResponse{Endpoints: endpoints, Before: before, Ready: processmetrics.Read()})
		return
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), cleanupTimeout)
	result := closeServers(cleanupCtx, servers)
	cleanupCancel()
	a.completeRun(completion, result)

	if err == nil {
		err = context.Canceled
	}
	http.Error(w, fmt.Sprintf("start routes: %v", errors.Join(err, result.drainErr, result.closeErr)), http.StatusInternalServerError)
}

func (a *agent) deleteRun(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), cleanupTimeout)
	defer cancel()
	result := a.closeRun(ctx)
	if result.closeErr != nil {
		http.Error(w, fmt.Sprintf("close routes: %v", result.closeErr), http.StatusInternalServerError)
		return
	}
	runtime.GC()
	runtime.GC()
	response := tailbench.CloseRunResponse{After: processmetrics.Read(), ForcedCloses: result.forced}
	if result.drainErr != nil {
		response.DrainError = result.drainErr.Error()
	}
	writeJSON(w, response)
}

func (a *agent) closeRun(ctx context.Context) closeResult {
	a.mu.Lock()
	switch a.state {
	case runIdle:
		a.mu.Unlock()
		return closeResult{}
	case runCreating:
		a.state = runClosing
		a.cancel()
		fallthrough
	case runClosing:
		completion := a.completion
		a.mu.Unlock()
		select {
		case <-completion.done:
			return completion.result
		case <-ctx.Done():
			return closeResult{closeErr: ctx.Err()}
		}
	case runActive:
		a.state = runClosing
		servers := a.servers
		a.servers = nil
		completion := &runCompletion{done: make(chan struct{})}
		a.completion = completion
		a.mu.Unlock()

		result := closeServers(ctx, servers)
		a.completeRun(completion, result)
		return result
	default:
		a.mu.Unlock()
		panic("invalid tailbench run state")
	}
}

func (a *agent) beginCreate(parent context.Context) (context.Context, *runCompletion, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopping {
		return nil, nil, errAgentStopping
	}
	if a.state != runIdle {
		return nil, nil, errRunAlreadyActive
	}
	ctx, cancel := context.WithCancel(parent)
	completion := &runCompletion{done: make(chan struct{})}
	a.state = runCreating
	a.cancel = cancel
	a.completion = completion
	return ctx, completion, nil
}

func (a *agent) activateRun(completion *runCompletion, servers []*tailtransport.Server) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.completion != completion {
		panic("mismatched tailbench run completion")
	}
	if a.state == runClosing {
		return false
	}
	if a.state != runCreating {
		panic("invalid tailbench run activation")
	}
	a.state = runActive
	a.cancel()
	a.cancel = nil
	a.servers = servers
	close(completion.done)
	a.completion = nil
	return true
}

func (a *agent) completeRun(completion *runCompletion, result closeResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.completion != completion || a.state != runCreating && a.state != runClosing {
		panic("invalid tailbench run completion")
	}
	if a.cancel != nil {
		a.cancel()
	}
	a.state = runIdle
	a.cancel = nil
	a.servers = nil
	completion.result = result
	close(completion.done)
	a.completion = nil
}

func (a *agent) shutdown(ctx context.Context) closeResult {
	a.mu.Lock()
	a.stopping = true
	a.mu.Unlock()
	return a.closeRun(ctx)
}

func closeServers(ctx context.Context, servers []*tailtransport.Server) closeResult {
	var forced atomic.Int64
	var drainMu sync.Mutex
	var drainErrs []error
	closeErr := parallel(len(servers), 8, func(index int) error {
		server := servers[index]
		if server == nil {
			return nil
		}
		drainCtx, cancel := context.WithTimeout(ctx, serverDrainTimeout)
		defer cancel()
		drainErr := server.Drain(drainCtx)
		if drainErr != nil {
			forced.Add(1)
			drainMu.Lock()
			drainErrs = append(drainErrs, fmt.Errorf("route %d: %w", index, drainErr))
			drainMu.Unlock()
		}
		closeErr := server.Close()
		servers[index] = nil
		return closeErr
	})
	return closeResult{forced: int(forced.Load()), drainErr: errors.Join(drainErrs...), closeErr: closeErr}
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
