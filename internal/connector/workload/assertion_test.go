package workload

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	"golang.org/x/sys/unix"
)

func TestAssertionSourceOneOfAndRotation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(" first.jwt.value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source := AssertionSource{TokenFile: file}
	if raw, err := source.Acquire(t.Context()); err != nil || raw != "first.jwt.value" {
		t.Fatal("file acquisition", err)
	}
	if err := os.WriteFile(file, []byte("second.jwt.value"), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := source.Acquire(t.Context()); err != nil || raw != "second.jwt.value" {
		t.Fatal("rotation was cached", err)
	}
	for _, s := range []AssertionSource{{}, {Assertion: "one", TokenFile: file}, {TokenFile: file, Callback: func(context.Context) (string, error) { return "callback", nil }}} {
		if _, err := s.Acquire(t.Context()); !errors.Is(err, ErrAssertionSource) {
			t.Fatal("ambiguous source accepted", err)
		}
	}
	t.Setenv("VERCEL_OIDC_TOKEN", "fallback.jwt.value")
	t.Setenv("VERCEL_OIDC_TOKEN_FILE", file)
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(t.Context(), workloadmanifest.Acquisition{Method: "vercel-oidc"}, nil, os.Getenv); !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("empty configured file fell back to env", err)
	}
	if raw, err := Acquire(t.Context(), workloadmanifest.Acquisition{Method: "vercel-oidc"}, func(context.Context) (string, error) { return "request.jwt.value", nil }, os.Getenv); err != nil || raw != "request.jwt.value" {
		t.Fatal("request callback did not own acquisition", err)
	}
	if _, err := (AssertionSource{Assertion: strings.Repeat("x", (32<<10)+1)}).Acquire(t.Context()); !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("oversized assertion accepted")
	}
}

func TestAssertionEnvironmentOverride(t *testing.T) {
	hints := workloadmanifest.Acquisition{Method: "token-env", TokenEnv: "JOB_ID_TOKEN"}
	for _, token := range []string{"first.private.jwt", "second.private.jwt"} {
		t.Setenv("JOB_ID_TOKEN", token)
		if actual, err := Acquire(t.Context(), hints, nil, os.Getenv); err != nil || actual != token {
			t.Fatal("environment source did not use current value", err)
		}
	}
	t.Setenv("JOB_ID_TOKEN", "")
	t.Setenv("VERCEL_OIDC_TOKEN", "fallback.private.jwt")
	if _, err := Acquire(t.Context(), hints, nil, os.Getenv); !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("missing selected environment fell back", err)
	}
	if _, err := Acquire(t.Context(), hints, func(context.Context) (string, error) { return "callback.private.jwt", nil }, os.Getenv); !errors.Is(err, ErrAssertionSource) {
		t.Fatal("ambiguous callback and env accepted", err)
	}
}

func TestFlyMachineTokenWire(t *testing.T) {
	var mu sync.Mutex
	reply, status, calls := "signed.machine.jwt\n", http.StatusOK, 0
	socket := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if r.Method != "POST" || r.URL.Path != "/v1/tokens/oidc" || r.Host != "localhost" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected machine token request")
		}
		var body struct {
			Audience string `json:"aud"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Audience != "https://fly.io/acme" {
			t.Error("wrong machine audience")
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Location", "/redirected")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	})}
	joined := make(chan struct{})
	go func() { defer close(joined); _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); <-joined })
	if raw, err := flyAssertion(t.Context(), "https://fly.io/acme", socket); err != nil || raw != "signed.machine.jwt" {
		t.Fatal("documented text token response rejected", err)
	}
	for _, invalid := range []string{strings.Repeat("x", 32<<10) + "\n", "private token", "\xff"} {
		mu.Lock()
		reply = invalid
		mu.Unlock()
		if _, err := flyAssertion(t.Context(), "https://fly.io/acme", socket); !errors.Is(err, ErrAssertionUnavailable) {
			t.Fatal("invalid Fly response accepted", err)
		}
	}
	mu.Lock()
	status, reply = http.StatusFound, "redirected"
	before := calls
	mu.Unlock()
	if _, err := flyAssertion(t.Context(), "https://fly.io/acme", socket); !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("redirect accepted", err)
	}
	mu.Lock()
	after := calls
	mu.Unlock()
	if after != before+1 {
		t.Fatal("Fly redirect was followed")
	}
}

func TestAssertionSourceRejectsNonRegularAndInvalidFiles(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "token")
	for _, data := range []string{"", " ", "private token", "private\x00token", "private\vtoken", "private\u00a0token", "private\ufefftoken", "\xff", strings.Repeat("x", 32769)} {
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := (AssertionSource{TokenFile: file}).Acquire(t.Context()); !errors.Is(err, ErrAssertionUnavailable) {
			t.Fatalf("invalid file accepted: %v", err)
		}
	}
	if _, err := (AssertionSource{TokenFile: root}).Acquire(t.Context()); !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("directory accepted", err)
	}
	fifo := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := (AssertionSource{TokenFile: fifo}).Acquire(t.Context()); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrAssertionUnavailable) {
			t.Fatal("FIFO accepted", err)
		}
	case <-time.After(time.Second):
		// release a regressed blocking open and join it before returning.
		fd, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
		<-done
		t.Fatal("FIFO blocked assertion acquisition")
	}
}

func TestGitHubAssertionWireAndBounds(t *testing.T) {
	var mu sync.Mutex
	var calls int
	var reply = `{"value":"signed.current.job"}`
	var status = http.StatusOK
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if r.Method != "GET" || r.URL.Path != "/token" || r.URL.Query().Get("audience") != "https://control.example.test" || r.URL.Query().Get("keep") != "yes" || r.Header.Get("Authorization") != "Bearer private-actions-bearer" {
			t.Error("wrong GitHub token request")
		}
		w.Header().Set("Location", "/redirected")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	defer server.Close()
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL+"/token?audience=wrong&keep=yes")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "private-actions-bearer")
	acquire := func() (string, error) {
		return githubAssertion(t.Context(), "https://control.example.test", server.Client().Transport, os.Getenv)
	}
	if token, err := acquire(); err != nil || token != "signed.current.job" {
		t.Fatal("valid GitHub response rejected", err)
	}
	for _, invalid := range []string{`{}`, `{"value":null}`, `{"value":1}`, `{"value":""}`, `{"value":"private token"}`, `{"value":"signed.current.job","extra":"private"}`, `{"value":"signed.current.job"} {}`, `{"value":"` + strings.Repeat("x", 32769) + `"}`, strings.Repeat(" ", (40<<10)+1)} {
		mu.Lock()
		reply = invalid
		mu.Unlock()
		if _, err := acquire(); !errors.Is(err, ErrAssertionUnavailable) {
			t.Fatal("invalid token response accepted", err)
		}
	}
	mu.Lock()
	reply, status = `{"value":"redirected"}`, http.StatusFound
	before := calls
	mu.Unlock()
	if _, err := acquire(); !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("token endpoint redirect was followed", err)
	}
	mu.Lock()
	after := calls
	mu.Unlock()
	if after != before+1 {
		t.Fatal("token endpoint redirect was followed")
	}
	for _, endpoint := range []string{"http://example.test/token", "https://user:private@example.test/token", "https://example.test/token#private", "https:///token"} {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", endpoint)
		if _, err := acquire(); !errors.Is(err, ErrAssertionUnavailable) {
			t.Fatal("invalid endpoint accepted", err)
		}
	}
	t.Setenv("GITHUB_ACTIONS", "false")
	if _, err := acquire(); !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("acquired outside Actions", err)
	}
	if token, err := Acquire(t.Context(), workloadmanifest.Acquisition{Method: "github-actions"}, func(context.Context) (string, error) { return "explicit.current.job", nil }, os.Getenv); err != nil || token != "explicit.current.job" {
		t.Fatal("explicit current-job callback rejected", err)
	}
}

func TestGitHubAssertionBodyProgressDoesNotExtendDeadline(t *testing.T) {
	joined := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(joined)
		w.WriteHeader(http.StatusOK)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
				_, _ = w.Write([]byte(" "))
				w.(http.Flusher).Flush()
			}
		}
	}))
	defer server.Close()
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "private-actions-bearer")
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := githubAssertion(ctx, "https://control.example.test", server.Client().Transport, os.Getenv); !errors.Is(err, ErrAssertionUnavailable) {
		t.Fatal("slow response accepted", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("body progress extended the deadline")
	}
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("request did not cancel its peer")
	}
}

func TestGitHubActionRefreshSourceValidationDoesNotAcquire(t *testing.T) {
	for _, test := range []struct {
		name, endpoint, token string
		valid                 bool
	}{
		{"private runtime", "https://runtime.example.test/token?keep=yes", "private-bearer", true},
		{"HTTP", "http://runtime.example.test/token", "private-bearer", false},
		{"userinfo", "https://user:secret@runtime.example.test/token", "private-bearer", false},
		{"fragment", "https://runtime.example.test/token#private", "private-bearer", false},
		{"missing host", "https:///token", "private-bearer", false},
		{"oversized URL", "https://runtime.example.test/" + strings.Repeat("x", 4096), "private-bearer", false},
		{"missing bearer", "https://runtime.example.test/token", "", false},
		{"invalid bearer", "https://runtime.example.test/token", "private\r\nbearer", false},
		{"oversized bearer", "https://runtime.example.test/token", strings.Repeat("x", (32<<10)+1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := map[string]string{"GITHUB_ACTIONS": "true", "ACTIONS_ID_TOKEN_REQUEST_URL": test.endpoint, "ACTIONS_ID_TOKEN_REQUEST_TOKEN": test.token}
			err := ValidateGitHubActionsSource(func(name string) string { return environment[name] })
			if (err == nil) != test.valid {
				t.Fatal("private job runtime validation changed its source bounds", err)
			}
		})
	}
}
