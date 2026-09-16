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
)

type coordinatorCommand struct {
	Listen           string        `name:"listen" env:"TNL_BENCH_COORDINATOR_LISTEN" default:":8080" help:"Coordinator HTTP listen address."`
	Token            string        `name:"token" env:"TNL_BENCH_COORDINATOR_TOKEN" required:"" help:"Coordinator bearer token."`
	CellID           string        `name:"cell-id" env:"TNL_BENCH_CELL_ID" required:"" help:"Expanded benchmark cell ID."`
	PublisherWorkers int           `name:"publisher-workers" env:"TNL_BENCH_PUBLISHER_WORKERS" required:"" help:"Expected publisher worker count."`
	LoadWorkers      int           `name:"load-workers" env:"TNL_BENCH_LOAD_WORKERS" required:"" help:"Expected load worker count."`
	ShutdownDelay    time.Duration `name:"shutdown-delay" env:"TNL_BENCH_SHUTDOWN_DELAY" default:"1h" help:"Maximum time to retain completed results for collection."`
}

func (c coordinatorCommand) Validate() error {
	if c.PublisherWorkers <= 0 || c.LoadWorkers <= 0 {
		return errors.New("publisher and load worker counts must be positive")
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
	mu                  sync.Mutex
	publishersReady     map[int]struct{}
	results             map[string]benchmarkResult
	publishersReadyWait chan struct{}
	loadDoneWait        chan struct{}
	abortedWait         chan struct{}
	publishersReadyOnce sync.Once
	loadDoneOnce        sync.Once
	abortedOnce         sync.Once
	failure             string
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
}

func newCoordinatorState(cellID string, publishers, load int) *coordinatorState {
	return &coordinatorState{
		cellID: cellID, publisherWorkers: publishers, loadWorkers: load,
		publishersReady: make(map[int]struct{}), results: make(map[string]benchmarkResult),
		publishersReadyWait: make(chan struct{}), loadDoneWait: make(chan struct{}), abortedWait: make(chan struct{}),
	}
}

func (c coordinatorCommand) run(ctx context.Context) error {
	state := newCoordinatorState(c.CellID, c.PublisherWorkers, c.LoadWorkers)
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
	mux.HandleFunc("GET /v1/wait/load", state.handleWaitLoad)
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
	s.mu.Lock()
	s.publishersReady[index] = struct{}{}
	ready := len(s.publishersReady) == s.publisherWorkers
	s.mu.Unlock()
	if ready {
		s.publishersReadyOnce.Do(func() { close(s.publishersReadyWait) })
	}
	response.WriteHeader(http.StatusNoContent)
}

func (s *coordinatorState) handleWaitPublishers(response http.ResponseWriter, request *http.Request) {
	s.wait(response, request, s.publishersReadyWait)
}

func (s *coordinatorState) handleWaitLoad(response http.ResponseWriter, request *http.Request) {
	s.wait(response, request, s.loadDoneWait)
}

func (s *coordinatorState) wait(response http.ResponseWriter, request *http.Request, ready <-chan struct{}) {
	select {
	case <-ready:
		response.WriteHeader(http.StatusNoContent)
	case <-s.abortedWait:
		s.mu.Lock()
		failure := s.failure
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

func (s *coordinatorState) handleResults(response http.ResponseWriter, _ *http.Request) {
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
	if !status.Complete {
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
	if s.failure != "" {
		status, complete = "failed", true
	} else if complete {
		status = "passed"
	}
	return coordinatorStatus{
		CellID: s.cellID, Status: status, PublishersReady: len(s.publishersReady),
		PublisherWorkers: s.publisherWorkers, PublisherResults: publishers,
		LoadWorkers: s.loadWorkers, LoadResults: loads, Complete: complete, Failure: s.failure,
	}
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

func (c *coordinatorClient) publisherReady(ctx context.Context, index int) error {
	return c.do(ctx, http.MethodPost, "/v1/publishers/ready?index="+strconv.Itoa(index), nil, http.StatusNoContent)
}

func (c *coordinatorClient) waitPublishers(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/v1/wait/publishers", nil, http.StatusNoContent)
}

func (c *coordinatorClient) waitLoad(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/v1/wait/load", nil, http.StatusNoContent)
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
