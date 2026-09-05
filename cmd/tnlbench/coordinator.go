package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/naming"
)

const coordinatorStatusFailureLimit = 4 << 10

type coordinatorCommand struct {
	Listen           string        `name:"listen" env:"TNL_BENCH_COORDINATOR_LISTEN" default:":8080" help:"Coordinator HTTP listen address."`
	Token            string        `name:"token" env:"TNL_BENCH_COORDINATOR_TOKEN" required:"" help:"Coordinator bearer token."`
	CellID           string        `name:"cell-id" env:"TNL_BENCH_CELL_ID" required:"" help:"Expanded benchmark cell ID."`
	PublisherWorkers int           `name:"publisher-workers" env:"TNL_BENCH_PUBLISHER_WORKERS" required:"" help:"Expected publisher worker count."`
	LoadWorkers      int           `name:"load-workers" env:"TNL_BENCH_LOAD_WORKERS" required:"" help:"Expected load worker count."`
	Routes           int           `name:"routes" env:"TNL_BENCH_ROUTES" required:"" help:"Expected registered route count."`
	ShutdownDelay    time.Duration `name:"shutdown-delay" env:"TNL_BENCH_SHUTDOWN_DELAY" default:"1h" help:"Maximum time to retain completed results for collection."`
}

func (c coordinatorCommand) Validate() error {
	if c.PublisherWorkers <= 0 || c.LoadWorkers <= 0 || c.Routes <= 0 {
		return errors.New("publisher and load worker and route counts must be positive")
	}
	if c.ShutdownDelay <= 0 {
		return errors.New("shutdown delay must be positive")
	}
	return nil
}

type coordinatorState struct {
	cellID              string
	publisherWorkers    int
	loadWorkers         int
	routeCount          int
	mu                  sync.Mutex
	publishersReady     map[int]struct{}
	routes              map[int]string
	results             map[string]benchmarkResult
	publishersReadyWait chan struct{}
	loadDoneWait        chan struct{}
	abortedWait         chan struct{}
	publishersReadyOnce sync.Once
	loadDoneOnce        sync.Once
	abortedOnce         sync.Once
	failure             string
	loadPhases          map[string]map[int]struct{}
	loadPhaseWait       map[string]chan struct{}
}

type coordinatorStatus struct {
	CellID           string `json:"cell_id"`
	Status           string `json:"status"`
	PublishersReady  int    `json:"publishers_ready"`
	PublisherWorkers int    `json:"publisher_workers"`
	PublisherResults int    `json:"publisher_results"`
	LoadWorkers      int    `json:"load_workers"`
	LoadResults      int    `json:"load_results"`
	Complete         bool   `json:"complete"`
	Failure          string `json:"failure,omitempty"`
	AbortCampaign    bool   `json:"abort_campaign,omitempty"`
}

type benchmarkRouteRegistration struct {
	Index    int    `json:"index"`
	Hostname string `json:"hostname"`
}

func newCoordinatorState(cellID string, publishers, load, routes int) *coordinatorState {
	state := &coordinatorState{
		cellID: cellID, publisherWorkers: publishers, loadWorkers: load, routeCount: routes,
		publishersReady: make(map[int]struct{}), routes: make(map[int]string), results: make(map[string]benchmarkResult),
		publishersReadyWait: make(chan struct{}), loadDoneWait: make(chan struct{}), abortedWait: make(chan struct{}),
	}
	state.loadPhases = make(map[string]map[int]struct{})
	state.loadPhaseWait = make(map[string]chan struct{})
	for _, phase := range []string{"prepared", "started", "finished", "collected"} {
		state.loadPhases[phase] = make(map[int]struct{})
		state.loadPhaseWait[phase] = make(chan struct{})
	}
	return state
}

func (c coordinatorCommand) run(ctx context.Context) error {
	state := newCoordinatorState(c.CellID, c.PublisherWorkers, c.LoadWorkers, c.Routes)
	server := &http.Server{Addr: c.Listen, Handler: coordinatorHandler(c.Token, state), ReadHeaderTimeout: 5 * time.Second}
	stopped := make(chan error, 1)
	go func() { stopped <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
	case err := <-stopped:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

func coordinatorHandler(token string, state *coordinatorState) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/publishers/ready", state.handlePublisherReady)
	mux.HandleFunc("GET /v1/wait/publishers", state.handleWaitPublishers)
	mux.HandleFunc("GET /v1/routes", state.handleRoutes)
	mux.HandleFunc("GET /v1/wait/load", state.handleWaitLoad)
	mux.HandleFunc("POST /v1/load/{phase}", state.handleLoadPhase)
	mux.HandleFunc("GET /v1/wait/load/{phase}", state.handleWaitLoadPhase)
	mux.HandleFunc("POST /v1/results", state.handleResult)
	mux.HandleFunc("GET /v1/results", state.handleResults)
	mux.HandleFunc("GET /v1/status", state.handleStatus)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if subtle.ConstantTimeCompare([]byte(request.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(response, request)
	})
}

func (s *coordinatorState) handlePublisherReady(response http.ResponseWriter, request *http.Request) {
	index, ok := workerIndex(response, request, s.publisherWorkers)
	if !ok {
		return
	}
	var registrations []benchmarkRouteRegistration
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registrations); err != nil {
		http.Error(response, "invalid route registrations", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(response, "invalid route registrations", http.StatusBadRequest)
		return
	}
	validated := make(map[int]string, len(registrations))
	for _, registration := range registrations {
		hostname, err := naming.CanonicalizeHostname(registration.Hostname)
		if err != nil || hostname != registration.Hostname || registration.Index < 0 || registration.Index >= s.routeCount {
			http.Error(response, "invalid route registration", http.StatusBadRequest)
			return
		}
		if _, exists := validated[registration.Index]; exists {
			http.Error(response, "duplicate route registration", http.StatusBadRequest)
			return
		}
		validated[registration.Index] = registration.Hostname
	}
	s.mu.Lock()
	if _, exists := s.publishersReady[index]; exists {
		s.mu.Unlock()
		http.Error(response, "publisher is already ready", http.StatusConflict)
		return
	}
	for routeIndex, hostname := range validated {
		if _, exists := s.routes[routeIndex]; exists || containsHostname(s.routes, hostname) {
			s.mu.Unlock()
			http.Error(response, "route registration conflicts", http.StatusConflict)
			return
		}
	}
	for routeIndex, hostname := range validated {
		s.routes[routeIndex] = hostname
	}
	s.publishersReady[index] = struct{}{}
	ready := len(s.publishersReady) == s.publisherWorkers
	if ready && len(s.routes) != s.routeCount {
		s.failure = fmt.Sprintf("publishers registered %d of %d routes", len(s.routes), s.routeCount)
	}
	failure := boundedCoordinatorFailure(s.failure)
	s.mu.Unlock()
	if failure != "" {
		s.abortedOnce.Do(func() { close(s.abortedWait) })
		http.Error(response, failure, http.StatusConflict)
		return
	}
	if ready {
		s.publishersReadyOnce.Do(func() { close(s.publishersReadyWait) })
	}
	response.WriteHeader(http.StatusNoContent)
}

func containsHostname(routes map[int]string, hostname string) bool {
	for _, candidate := range routes {
		if candidate == hostname {
			return true
		}
	}
	return false
}

func (s *coordinatorState) handleRoutes(response http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	if len(s.publishersReady) != s.publisherWorkers || len(s.routes) != s.routeCount {
		s.mu.Unlock()
		http.Error(response, "publisher routes are not ready", http.StatusTooEarly)
		return
	}
	routes := make([]string, s.routeCount)
	for index, hostname := range s.routes {
		routes[index] = hostname
	}
	s.mu.Unlock()
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(routes)
}

func (s *coordinatorState) handleWaitPublishers(response http.ResponseWriter, request *http.Request) {
	s.wait(response, request, s.publishersReadyWait)
}

func (s *coordinatorState) handleWaitLoad(response http.ResponseWriter, request *http.Request) {
	s.wait(response, request, s.loadDoneWait)
}

// All workers finish setup before the baseline scrape. None starts recovery or
// teardown until every fresh workload has finished and the final scrape is done.
func (s *coordinatorState) handleLoadPhase(response http.ResponseWriter, request *http.Request) {
	index, ok := workerIndex(response, request, s.loadWorkers)
	if !ok {
		return
	}
	phase := request.PathValue("phase")
	s.mu.Lock()
	defer s.mu.Unlock()
	arrived, ok := s.loadPhases[phase]
	if !ok {
		http.Error(response, "invalid load phase", http.StatusBadRequest)
		return
	}
	if s.failure != "" {
		http.Error(response, boundedCoordinatorFailure(s.failure), http.StatusConflict)
		return
	}
	if _, duplicate := arrived[index]; duplicate {
		response.WriteHeader(http.StatusNoContent)
		return
	}
	valid, required := true, s.loadWorkers
	switch phase {
	case "started":
		valid, required = index == 0 && len(s.loadPhases["prepared"]) == s.loadWorkers, 1
	case "finished":
		valid = len(s.loadPhases["started"]) == 1
	case "collected":
		valid, required = index == 0 && len(s.loadPhases["finished"]) == s.loadWorkers, 1
	}
	if !valid {
		http.Error(response, "load phase is not ready or worker is not its owner", http.StatusConflict)
		return
	}
	arrived[index] = struct{}{}
	if len(arrived) == required {
		close(s.loadPhaseWait[phase])
	}
	response.WriteHeader(http.StatusNoContent)
}

func (s *coordinatorState) handleWaitLoadPhase(response http.ResponseWriter, request *http.Request) {
	// Channels are installed at construction and never replaced.
	ready, ok := s.loadPhaseWait[request.PathValue("phase")]
	if !ok {
		http.Error(response, "invalid load phase", http.StatusBadRequest)
		return
	}
	s.wait(response, request, ready)
}

func (s *coordinatorState) wait(response http.ResponseWriter, request *http.Request, ready <-chan struct{}) {
	select {
	case <-ready:
		response.WriteHeader(http.StatusNoContent)
	case <-s.abortedWait:
		s.mu.Lock()
		failure := boundedCoordinatorFailure(s.failure)
		s.mu.Unlock()
		http.Error(response, failure, http.StatusConflict)
	case <-request.Context().Done():
	}
}

func (s *coordinatorState) handleResult(response http.ResponseWriter, request *http.Request) {
	var result benchmarkResult
	decoder := json.NewDecoder(io.LimitReader(request.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		http.Error(response, "invalid result", http.StatusBadRequest)
		return
	}
	if result.SchemaVersion != benchmarkResultSchemaVersion || result.CellID != s.cellID ||
		(result.Worker.Kind != "publisher" && result.Worker.Kind != "load") {
		http.Error(response, "result identity does not match coordinator", http.StatusBadRequest)
		return
	}
	want := s.publisherWorkers
	if result.Worker.Kind == "load" {
		want = s.loadWorkers
	}
	if result.Worker.Count != want || result.Worker.Index < 0 || result.Worker.Index >= want {
		http.Error(response, "invalid result worker", http.StatusBadRequest)
		return
	}
	key := result.Worker.Kind + ":" + strconv.Itoa(result.Worker.Index)
	s.mu.Lock()
	if _, exists := s.results[key]; exists {
		s.mu.Unlock()
		http.Error(response, "result already recorded", http.StatusConflict)
		return
	}
	if result.Failure != nil {
		result.Failure.Message = boundedCoordinatorFailure(result.Failure.Message)
	}
	s.results[key] = result
	loadResults := s.resultCountLocked("load")
	if result.Status != "passed" && s.failure == "" {
		if result.Failure != nil {
			s.failure = result.Failure.Message
		} else {
			s.failure = key + " failed"
		}
	}
	failure := s.failure
	s.mu.Unlock()
	if loadResults == s.loadWorkers {
		s.loadDoneOnce.Do(func() { close(s.loadDoneWait) })
	}
	if failure != "" {
		s.abortedOnce.Do(func() { close(s.abortedWait) })
	}
	response.WriteHeader(http.StatusNoContent)
}

func (s *coordinatorState) handleResults(response http.ResponseWriter, request *http.Request) {
	s.mu.Lock()
	status := s.statusLocked()
	results := make([]benchmarkResult, 0, len(s.results))
	for _, kind := range []string{"publisher", "load"} {
		count := s.publisherWorkers
		if kind == "load" {
			count = s.loadWorkers
		}
		for index := range count {
			if result, found := s.results[kind+":"+strconv.Itoa(index)]; found {
				results = append(results, result)
			}
		}
	}
	s.mu.Unlock()
	if !status.Complete && request.URL.Query().Get("partial") != "1" {
		http.Error(response, "benchmark is not complete", http.StatusTooEarly)
		return
	}
	response.Header().Set("Content-Type", "application/x-ndjson")
	encoder := json.NewEncoder(response)
	for _, result := range results {
		if err := encoder.Encode(result); err != nil {
			return
		}
	}
}

func (s *coordinatorState) handleStatus(response http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	status := s.statusLocked()
	s.mu.Unlock()
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(status)
}

func (s *coordinatorState) statusLocked() coordinatorStatus {
	publishers := s.resultCountLocked("publisher")
	loads := s.resultCountLocked("load")
	status := "running"
	complete := publishers == s.publisherWorkers && loads == s.loadWorkers
	abort := false
	for _, result := range s.results {
		if stage := resultFailureStage(result); stage != "" && stage != "measurement" {
			abort = true
		}
	}
	if s.failure != "" {
		status = "failed"
	} else if complete {
		status = "passed"
	}
	return coordinatorStatus{
		CellID: s.cellID, Status: status, PublishersReady: len(s.publishersReady),
		PublisherWorkers: s.publisherWorkers, PublisherResults: publishers,
		LoadWorkers: s.loadWorkers, LoadResults: loads, Complete: complete, Failure: boundedCoordinatorFailure(s.failure),
		AbortCampaign: abort,
	}
}

func boundedCoordinatorFailure(value string) string {
	if len(value) <= coordinatorStatusFailureLimit {
		return value
	}
	limit := coordinatorStatusFailureLimit
	for !utf8.ValidString(value[:limit]) {
		limit--
	}
	return value[:limit] + "\n[truncated]"
}

func (s *coordinatorState) resultCountLocked(kind string) int {
	count := 0
	for key := range s.results {
		if len(key) > len(kind) && key[:len(kind)+1] == kind+":" {
			count++
		}
	}
	return count
}

func workerIndex(response http.ResponseWriter, request *http.Request, count int) (int, bool) {
	index, err := strconv.Atoi(request.URL.Query().Get("index"))
	if err != nil || index < 0 || index >= count {
		http.Error(response, "invalid worker index", http.StatusBadRequest)
		return 0, false
	}
	return index, true
}

type coordinatorClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func newCoordinatorClient(rawURL, token string) (*coordinatorClient, error) {
	endpoint, err := url.Parse(rawURL)
	if err != nil || endpoint.Scheme != "http" && endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil {
		return nil, errors.New("coordinator URL must be an HTTP or HTTPS origin")
	}
	if endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("coordinator URL must not include a path, query, or fragment")
	}
	return &coordinatorClient{baseURL: endpoint.String(), token: token, client: &http.Client{Timeout: 35 * time.Minute}}, nil
}

func (c *coordinatorClient) publisherReady(ctx context.Context, index int, routes []benchmarkRouteRegistration) error {
	body, err := json.Marshal(routes)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, "/v1/publishers/ready?index="+strconv.Itoa(index), bytes.NewReader(body), http.StatusNoContent)
}

func (c *coordinatorClient) waitPublishers(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/v1/wait/publishers", nil, http.StatusNoContent)
}

func (c *coordinatorClient) waitLoad(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/v1/wait/load", nil, http.StatusNoContent)
}

func (c *coordinatorClient) loadPhase(ctx context.Context, phase string, index int) error {
	return c.do(ctx, http.MethodPost, "/v1/load/"+phase+"?index="+strconv.Itoa(index), nil, http.StatusNoContent)
}

func (c *coordinatorClient) waitLoadPhase(ctx context.Context, phase string) error {
	return c.do(ctx, http.MethodGet, "/v1/wait/load/"+phase, nil, http.StatusNoContent)
}

func (c *coordinatorClient) routes(ctx context.Context) ([]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/routes", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return nil, errors.Join(fmt.Errorf("coordinator routes: HTTP %d: %s", response.StatusCode, data), readErr)
	}
	var routes []string
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&routes); err != nil {
		return nil, err
	}
	return routes, nil
}

func (c *coordinatorClient) postResult(ctx context.Context, result benchmarkResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, "/v1/results", bytes.NewReader(data), http.StatusNoContent)
}

func (c *coordinatorClient) do(ctx context.Context, method, path string, body io.Reader, want int) error {
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	closeErr := response.Body.Close()
	if response.StatusCode != want {
		return errors.Join(fmt.Errorf("coordinator %s: HTTP %d: %s", path, response.StatusCode, data), readErr, closeErr)
	}
	return errors.Join(readErr, closeErr)
}
