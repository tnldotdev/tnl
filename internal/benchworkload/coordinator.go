package benchworkload

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
	"strings"
	"sync"
	"time"
)

// Coordinator stores immutable run events. The runner owns the phase sequence;
// participants acknowledge readiness/results under their own event names.
type Coordinator struct {
	mu      sync.Mutex
	events  map[string]json.RawMessage
	changed chan struct{}
	failure string
}

func NewCoordinator() *Coordinator {
	return &Coordinator{events: make(map[string]json.RawMessage), changed: make(chan struct{})}
}

func (s *Coordinator) Handler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/v1/events/")
		if !strings.HasPrefix(r.URL.Path, "/v1/events/") || len(name) == 0 || len(name) > 128 || strings.ContainsAny(name, "/\\\n\r") {
			http.Error(w, "invalid event name", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
			if err != nil || !json.Valid(data) {
				http.Error(w, "invalid event JSON", http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if previous, found := s.events[name]; found {
				if bytes.Equal(previous, data) {
					w.WriteHeader(http.StatusNoContent)
				} else {
					http.Error(w, "event already recorded", http.StatusConflict)
				}
				return
			}
			if len(s.events) >= 4096 {
				http.Error(w, "event limit exceeded", http.StatusConflict)
				return
			}
			if name == "failure" {
				var message string
				if json.Unmarshal(data, &message) != nil || message == "" || len(message) > 4096 {
					http.Error(w, "invalid failure", http.StatusBadRequest)
					return
				}
				s.failure = message
			}
			s.events[name] = data
			close(s.changed)
			s.changed = make(chan struct{})
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			timer := time.NewTimer(10 * time.Second)
			defer timer.Stop()
			for {
				s.mu.Lock()
				value, exists := s.events[name]
				failure, changed := s.failure, s.changed
				s.mu.Unlock()
				if exists {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(value)
					return
				}
				if r.URL.Query().Get("wait") != "1" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if failure != "" {
					http.Error(w, failure, http.StatusConflict)
					return
				}
				select {
				case <-changed:
				case <-timer.C:
					w.WriteHeader(http.StatusAccepted)
					return
				case <-r.Context().Done():
					return
				}
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

type Coordination struct {
	endpoint, token string
	client          *http.Client
}

func NewCoordination(endpoint, token string) (*Coordination, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || token == "" {
		return nil, errors.New("coordinator requires an HTTP origin and bearer token")
	}
	return &Coordination{endpoint: endpoint, token: token, client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Coordination) Put(ctx context.Context, name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, status, err := c.request(ctx, http.MethodPut, name, false, data)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("coordinator put %s: HTTP %d", name, status)
	}
	return nil
}

func (c *Coordination) Get(ctx context.Context, name string, value any) (bool, error) {
	data, status, err := c.request(ctx, http.MethodGet, name, false, nil)
	if err != nil {
		return false, err
	}
	if status == http.StatusNotFound {
		return false, nil
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("coordinator get %s: HTTP %d", name, status)
	}
	if value != nil {
		err = json.Unmarshal(data, value)
	}
	return true, err
}

func (c *Coordination) Wait(ctx context.Context, name string, value any) error {
	for {
		data, status, err := c.request(ctx, http.MethodGet, name, true, nil)
		if err != nil {
			return err
		}
		if status == http.StatusAccepted {
			continue
		}
		if status != http.StatusOK {
			return fmt.Errorf("coordinator wait %s: HTTP %d: %s", name, status, data)
		}
		if value != nil {
			return json.Unmarshal(data, value)
		}
		return nil
	}
}

// WorkloadContext also stops participants already running a measurement. Stop
// joins the watcher; cleanup uses a separate context to report its outcome.
func (c *Coordination) WorkloadContext(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var failure string
		err := c.Wait(ctx, "failure", &failure)
		if ctx.Err() == nil {
			if err == nil {
				err = errors.New(failure)
			}
			cancel(err)
		}
	}()
	return ctx, func() { cancel(context.Canceled); <-done }
}

func (c *Coordination) request(ctx context.Context, method, name string, wait bool, data []byte) ([]byte, int, error) {
	endpoint := c.endpoint + "/v1/events/" + url.PathEscape(name)
	if wait {
		endpoint += "?wait=1"
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	response, err := c.client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if len(body) > 16<<20 {
		return nil, 0, errors.New("coordinator response exceeds limit")
	}
	return body, response.StatusCode, err
}

// Phase is sent by the coordinator. Participants do not carry their own copy of
// the scenario sequence. A zero duration requests correctness probes only.
type Phase struct {
	Name        string           `json:"name"`
	Start       time.Time        `json:"start"`
	Duration    time.Duration    `json:"duration"`
	URLs        []string         `json:"urls"`
	Bandwidth   *BandwidthConfig `json:"bandwidth,omitempty"`
	Combined    bool             `json:"combined,omitempty"`
	Direct      bool             `json:"direct,omitempty"`
	HeldStreams int              `json:"held_streams,omitempty"`
	CloseHeld   bool             `json:"close_held,omitempty"`
	OpenHeld    bool             `json:"open_held,omitempty"`
	Done        bool             `json:"done,omitempty"`
}

func Assignment(total, count, index int) int {
	value := total / count
	if index < total%count {
		value++
	}
	return value
}

func RouteIndexes(total, count, index int) []int {
	var indexes []int
	for i := index; i < total; i += count {
		indexes = append(indexes, i)
	}
	return indexes
}
